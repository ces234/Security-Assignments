import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    private static final String PASSWORD_FILE = "passwords.txt"; // Example file name

    public static void main(String[] args) throws Exception {

        File file = new File(PASSWORD_FILE);
        boolean fileExists = file.exists();


        Scanner scanner = new Scanner(System.in);

        if (fileExists) {
            // Password file exists, prompt for password
            System.out.println("Enter the passcode to access your passwords: ");
            String enteredPassword = scanner.nextLine();
            BufferedReader reader = new BufferedReader(new FileReader(PASSWORD_FILE));
            String[] parts = reader.readLine().split(":");
            String salt = parts[0];
            String token = parts[1];

            if (!verifyPassword(enteredPassword.toCharArray(), salt, token)) {
                System.out.println("Incorrect password. Access denied. ");
            }
            else{
                System.out.println("correct password. ");
            }
        } else {
            // Password file does not exist, prompt for initial password
            System.out.println("No password file found. Enter an initial password: ");
            String initialPassword = scanner.nextLine();
            try{
                String salt = generateSalt();
                String token = hashPassword(initialPassword.toCharArray(), Base64.getDecoder().decode(salt));

                createPasswordFile(salt, token);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static boolean verifyPassword(char[] enteredPassword, String storedSalt, String storedToken) throws Exception {
        String hashedEnteredPassword = hashPassword(enteredPassword, Base64.getDecoder().decode(storedSalt));
        return hashedEnteredPassword.equals(storedToken);
    }

    private static void createPasswordFile(String salt, String token) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(PASSWORD_FILE));
        writer.write(salt + ":" + token);
        writer.newLine();
        writer.close();
    }

    private static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private static String hashPassword(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = factory.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(hash);
    }
}
