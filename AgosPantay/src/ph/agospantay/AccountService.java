package ph.agospantay;

import java.util.Locale;
import java.util.Optional;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;

@Service
class AccountService implements UserDetailsService {
    private static final String ADMIN_USERNAME = "admin";

    private record Account(String username, String passwordHash, String role, Long residentId, String status) {}

    record Session(String username, String role, Long residentId, String name, String page) {}

    private final JdbcClient jdbc;
    private final ResidentRepository residents;
    private final CommunityRepository community;
    private final PasswordEncoder passwords;

    AccountService(JdbcClient jdbc, ResidentRepository residents, CommunityRepository community, PasswordEncoder passwords) {
        this.jdbc = jdbc;
        this.residents = residents;
        this.community = community;
        this.passwords = passwords;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        Account account = find(username).orElseThrow(() -> new UsernameNotFoundException("Account not found."));
        return User.withUsername(account.username()).password(account.passwordHash()).roles(account.role())
            .disabled("Pending".equals(account.status())).build();
    }

    @Transactional
    public void register(JsonNode body) {
        String username = Input.required(body, "username", "Username", 32);
        if (!username.matches("[A-Za-z0-9_.-]{3,32}")) {
            throw ApiProblem.badRequest("Use 3–32 letters, numbers, periods, underscores, or hyphens for your username.");
        }
        String normalizedUsername = normalize(username);
        if (ADMIN_USERNAME.equals(normalizedUsername)) {
            throw ApiProblem.conflict("That username is reserved for the administrator.");
        }
        String role = Input.optional(body, "role", "Account role", 32);
        if (role.isEmpty()) {
            throw ApiProblem.badRequest("Select an account role.");
        }
        if (!"community_member".equals(role) && !"RESIDENT".equalsIgnoreCase(role)) {
            throw ApiProblem.badRequest("Public registration creates resident accounts.");
        }
        JsonNode passwordNode = body.path("password");
        String password = passwordNode.isTextual() ? passwordNode.asText() : "";
        if (password.length() < 8 || password.length() > 128) {
            throw ApiProblem.badRequest("Use a password with 8–128 characters.");
        }
        String passwordHash = passwords.encode(password);
        ResidentProfile profile = residents.create(username, "", "", "", "Active");
        try {
            insert(normalizedUsername, passwordHash, "RESIDENT", profile.id());
        } catch (DuplicateKeyException e) {
            throw ApiProblem.conflict("That username is already registered.");
        }
        community.audit(normalizedUsername, "Registered a new resident account (" + normalizedUsername + ")");
    }

    Session session(String username) {
        Account account = find(username).orElseThrow(
            () -> new ApiProblem(HttpStatus.UNAUTHORIZED, "Sign in to continue.")
        );
        if (account.residentId() == null) {
            return new Session(account.username(), "water_manager", null, "System Administrator", "/admin.html");
        }
        ResidentProfile profile = activeProfile(account.residentId(), false);
        return new Session(account.username(), "community_member", profile.id(), profile.name(), "/resident.html");
    }

    ResidentProfile resident(String username, boolean lock) {
        Long residentId = find(username).map(Account::residentId).orElseThrow(
            () -> new ApiProblem(HttpStatus.FORBIDDEN, "A resident account is required.")
        );
        return activeProfile(residentId, lock);
    }

    boolean adminExists() {
        return find(ADMIN_USERNAME).isPresent();
    }

    void createAdmin(String password) {
        insert(ADMIN_USERNAME, passwords.encode(password), "ADMIN", null);
    }

    boolean updateAdminPassword(String password) {
        Account admin = find(ADMIN_USERNAME).orElseThrow();
        if (passwords.matches(password, admin.passwordHash())) return false;
        return jdbc.sql("UPDATE accounts SET password_hash = ? WHERE username = ? AND role = 'ADMIN'")
            .param(passwords.encode(password)).param(ADMIN_USERNAME).update() == 1;
    }

    private ResidentProfile activeProfile(long id, boolean lock) {
        ResidentProfile profile = lock ? residents.lock(id) : residents.get(id);
        if (!profile.active()) {
            throw new ApiProblem(HttpStatus.FORBIDDEN, "Your resident account is pending. Contact your administrator.");
        }
        return profile;
    }

    private void insert(String username, String passwordHash, String role, Long residentId) {
        jdbc.sql("INSERT INTO accounts (username, password_hash, role, resident_id) VALUES (?, ?, ?, ?)")
            .param(1, normalize(username)).param(2, passwordHash).param(3, role)
            .param(4, residentId, java.sql.Types.BIGINT).update();
    }

    private Optional<Account> find(String username) {
        return jdbc.sql("""
                SELECT a.username, a.password_hash, a.role, a.resident_id, r.status
                FROM accounts a LEFT JOIN residents r ON r.id = a.resident_id WHERE a.username = ?
                """)
            .param(normalize(username))
            .query((row, index) -> new Account(row.getString("username"), row.getString("password_hash"),
                row.getString("role"), row.getObject("resident_id", Long.class), row.getString("status")))
            .optional();
    }

    private String normalize(String username) {
        return username.strip().toLowerCase(Locale.ROOT);
    }
}

