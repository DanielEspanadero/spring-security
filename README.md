# Spring Security - JWT (Autenticación y autorización)

![Demo](https://github.com/DanielEspanadero/spring-security/blob/main/documents/spring-security.png)

En este tutorial aprenderás:

- Implementación de **Spring Security**
- Configuración de llaves públicas y privadas con OpenSSL
- Login y Registro con **Json Web Token**
- Autorizar el acceso a un endpoint a usuarios logueados
- Configuración de **CORS** para que el Front-end pueda acceder a tu proyecto


<br>


Al loguearse el usuario, si las credenciales (usuario y contraseña) son válidas, se devolverá en la respuesta un JWT.<br>

## ¿Qué es OpenSSL?

![Demo](https://github.com/DanielEspanadero/spring-security/blob/main/documents/OpenSSL.png)

OpenSSL es una biblioteca de código abierto que proporciona implementaciones de protocolos criptográficos y funciones criptográficas en diversos lenguajes de programación. Esta biblioteca se utiliza comúnmente para implementar protocolos de seguridad como SSL (Secure Sockets Layer) y su sucesor, TLS (Transport Layer Security), que se utilizan para asegurar las comunicaciones en redes, como por ejemplo, las transacciones en línea y la transmisión segura de datos.

Además de los protocolos de seguridad, OpenSSL también incluye una amplia gama de funciones criptográficas, como generación de claves, cifrado y descifrado, funciones de resumen (hashing), y más. Es una herramienta fundamental en el desarrollo de aplicaciones seguras y se utiliza en una variedad de entornos, desde servidores web hasta aplicaciones de seguridad en redes.

### ¿Por qué generar las llaves de nuestros JWT con OpenSSL y no con strings u otros métodos?

OpenSSL utiliza algoritmos criptográficos robustos y métodos específicos para garantizar la fortaleza de las claves generadas. Además, proporciona funciones para la gestión segura de claves, como la generación aleatoria de números primos.

Además, OpenSSL implementa estándares de seguridad reconocidos, lo que significa que las claves generadas cumplen con criterios rigurosos y son compatibles con una amplia variedad de sistemas y aplicaciones.

Generar claves con strings u otros métodos caseros puede ser riesgoso, ya que no garantiza la aleatoriedad necesaria para la fortaleza criptográfica. La aleatoriedad es crucial para evitar patrones predecibles que podrían ser explotados por atacantes.

### ¿Cómo generar private_key.pem y public_key.pem con OpenSSL?

Recuerda guardad las llaves privadas y públicas dentro de la carpeta resources/jwtKeys

Generación de la llave privada:
```
openssl genrsa -out private_key.pem 2048
```

Generación de la llave pública a través de la llave privada:
```
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

## application.properties

Para poder arrancar la aplicación correctamente, recuerda tener creada una BBDD llamada security y cambiar el password por el que tengas configurado en tu sistema.

```
spring.jpa.hibernate.ddl-auto=update
spring.datasource.url=jdbc:mysql://localhost:3306/security?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrival=true
spring.datasource.username=root
spring.datasource.password=#De123456789.
spring.jpa.database-platform=org.hibernate.dialect.MySQL8Dialect
jwtKeys.privateKeyPath=jwtKeys/private.key.pem
jwtKeys.publicKeyPath=jwtKeys/public.key.pem
```

## persistencia

Para este ejemplo, he creado lo mínimo posible para entender de una manera correcta spring security, no hay validaciones de email ni de password, simplemente es un ejemplo educativo.

### LoginDTO

```
public class LoginDTO {
    private String email;
    private String password;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
```

### UserEntity

```
@Entity
@Table(name = "user")
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;
    @Column(name = "first_name")
    private String firstName;
    @Column(name = "last_name")
    private String lastName;
    private String email;
    private String password;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
```

### UserRepository

```
public interface UserRepository extends JpaRepository<UserEntity, Long> {

    @Query(value = "SELECT * FROM user WHERE email = :email", nativeQuery = true)
    Optional<UserEntity> findByEmail(String email);
}
```

## Configuración de cors

### CorsConfig

```
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:4200")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("Origin", "Content-Type", "Accept", "Authorization")
                .allowCredentials(true)
                .maxAge(3600);

        registry.addMapping("/auth/**")
                .allowedOrigins("*")
                .allowedMethods("OPTIONS", "POST")
                .allowedHeaders("Origin", "Content-Type", "Accept", "Authorization")
                .allowCredentials(false)
                .maxAge(3600);
    }
}
```

## JWT

### JWTUtilityServiceImpl

```
@Service
public class JWTUtilityServiceImpl implements IJWTUtilityService {

    @Value("classpath:jwtKeys/private_key.pem")
    private Resource privateKeyResource;

    @Value("classpath:jwtKeys/public_key.pem")
    private Resource publicKeyResource;

    @Override
    public String generateJWT(Long userId) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        PrivateKey privateKey = loadPrivateKey(privateKeyResource);

        JWSSigner signer = new RSASSASigner(privateKey);

        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(userId.toString())
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 14400000))
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    @Override
    public JWTClaimsSet parseJWT(String jwt) throws JOSEException, IOException, ParseException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = loadPublicKey(publicKeyResource);

        SignedJWT signedJWT = SignedJWT.parse(jwt);

        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        if (!signedJWT.verify(verifier)) {
            throw new JOSEException("Invalid signature");
        }

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        if (claimsSet.getExpirationTime().before(new Date())) {
            throw new JOSEException("Expired token");
        }

        return claimsSet;
    }

    private PrivateKey loadPrivateKey(Resource resource) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));
        String privateKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }

    private PublicKey loadPublicKey(Resource resource) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));
        String publicKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    }
}
```

## Security

### JWTAutorizationFilter

```
public class JWTAuthorizationFilter extends OncePerRequestFilter {

    public JWTAuthorizationFilter(JWTUtilityServiceImpl jwtUtilityService) {
        this.jwtUtilityService = jwtUtilityService;
    }

    @Autowired
    JWTUtilityServiceImpl jwtUtilityService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7); // Extract the token excluding "Bearer "

        try {
            JWTClaimsSet claims = jwtUtilityService.parseJWT(token);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(claims.getSubject(), null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        } catch (JOSEException | ParseException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        filterChain.doFilter(request, response);
    }
}
```

### SecurityConfiguration

```
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfiguration {
    @Autowired
    private IJWTUtilityService jwtUtilityService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf ->
                        csrf.disable())
                .authorizeHttpRequests(authRequest ->
                        authRequest
                                .requestMatchers("/auth/**").permitAll()
                                .anyRequest().authenticated()
                )
                .sessionManagement(sessionManager ->
                        sessionManager
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new JWTAuthorizationFilter((JWTUtilityServiceImpl) jwtUtilityService), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling
                                .authenticationEntryPoint((request, response, authException) -> {
                                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                                }))
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

## Login and register

### AuthServiceImpl

```
@Service
public class AuthServiceImpl implements IAuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private IJWTUtilityService jwtUtilityService;

    @Override
    public HashMap<String, String> login(LoginDTO loginRequest) throws Exception {
        try {
            HashMap<String, String> jwt = new HashMap<>();
            Optional<UserEntity> user = userRepository.findByEmail(loginRequest.getEmail());

            if (user.isEmpty()) {
                jwt.put("error", "User not registered!");
                return jwt;
            }
            if (verifyPassword(loginRequest.getPassword(), user.get().getPassword())) {
                jwt.put("jwt", jwtUtilityService.generateJWT(user.get().getId()));
            } else {
                jwt.put("error", "Authentication failed");
            }
            return jwt;
        } catch (IllegalArgumentException e) {
            System.err.println("Error generating JWT: " + e.getMessage());
            throw new Exception("Error generating JWT", e);
        } catch (Exception e) {
            System.err.println("Unknown error: " + e.toString());
            throw new Exception("Unknown error", e);
        }
    }

    @Override
    public HashMap<String, String> register(UserEntity user) throws Exception {
        try {
            HashMap<String, String> response = new HashMap<>();
            List<UserEntity> getAllUsers = userRepository.findAll();

            for (UserEntity repeatFields : getAllUsers) {
                if (repeatFields != null) {
                    response.put("message", "User already exists!");
                    return response;
                }
            }

            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
            user.setPassword(encoder.encode(user.getPassword()));

            userRepository.save(user);
            response.put("message", "User created successfully!");
            return response;
        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }
    }

    private boolean verifyPassword(String enteredPassword, String storedPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.matches(enteredPassword, storedPassword);
    }
}
```

### AuthController

```
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private IAuthService authService;

    @PostMapping("/register")
    private ResponseEntity<HashMap<String, String>> addUser(@RequestBody UserEntity user) throws Exception {
        return new ResponseEntity<>(authService.register(user), HttpStatus.OK);
    }

    @PostMapping("/login")
    private ResponseEntity<HashMap<String, String>> login(@RequestBody LoginDTO loginRequest) throws Exception {
        HashMap<String, String> login = authService.login(loginRequest);
        if (login.containsKey("jwt")) {
            return new ResponseEntity<>(authService.login(loginRequest), HttpStatus.ACCEPTED);
        } else {
            return new ResponseEntity<>(authService.login(loginRequest), HttpStatus.UNAUTHORIZED);
        }
    }
}
```


## Private route

### UserServiceImpl

```
@Service
public class UserServiceImpl implements IUserService {

    @Autowired
    UserRepository userRepository;

    @Override
    public List<UserEntity> findAllUsers(){
        return userRepository.findAll();
    }
}
```

### UserController

```
@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    IUserService userService;

    @GetMapping("/all")
    private ResponseEntity<List<UserEntity>> getAllUsers(){
        return new ResponseEntity<>(userService.findAllUsers(), HttpStatus.OK);
    }
}
```