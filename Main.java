import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Map;
import java.util.HashMap;

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
            } else {
                while (true) {
                    System.out.println("Do you want to add a password(A), read a password(R), or quit(Q)");
                    String function = scanner.nextLine();
                    if (function.equals("A")) {
                        System.out.println("(A): Add a Password");
                        System.out.println("Please provide a password label:");
                        String label = scanner.nextLine();
                        System.out.println("Please provide a password:");
                        String password = scanner.nextLine();
                        addPassword(enteredPassword, label, password, null);
                    } else if (function.equals("R")) {
                        System.out.println("(R): Read a Password");
                        System.out.println("Enter the label of the password you would like to see:");
                        String label = scanner.nextLine();
                        String password = readPassword(enteredPassword, label, null);
                        System.out.println(password);
                    } else if (function.equals("Q")) {
                        System.out.println("Quitting Manager...");
                        System.exit(0);
                    } else {
                        System.out.println("Not a valid command.");
                    }
                }}
            }
        else{
                // Password file does not exist, prompt for initial password
                System.out.println("No password file found. Enter an initial password: ");
                String initialPassword = scanner.nextLine();
                try {
                    String salt = generateSalt();
                    String token = hashPassword(initialPassword.toCharArray(), Base64.getDecoder().decode(salt));

                    createPasswordFile(salt, token);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }


            private static boolean verifyPassword ( char[] enteredPassword, String storedSalt, String storedToken) throws Exception {
                String hashedEnteredPassword = hashPassword(enteredPassword, Base64.getDecoder().decode(storedSalt));
                return hashedEnteredPassword.equals(storedToken);
            }

            private static void createPasswordFile (String salt, String token) throws IOException {
                BufferedWriter writer = new BufferedWriter(new FileWriter(PASSWORD_FILE));
                writer.write(salt + ":" + token);
                writer.newLine();
                writer.close();
            }

            private static String generateSalt () {
                SecureRandom random = new SecureRandom();
                byte[] salt = new byte[16];
                random.nextBytes(salt);
                return Base64.getEncoder().encodeToString(salt);
            }

            private static String hashPassword ( char[] password, byte[] salt) throws Exception {
                PBEKeySpec spec = new PBEKeySpec(password, salt, 600000, 128);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] hash = factory.generateSecret(spec).getEncoded();
                return Base64.getEncoder().encodeToString(hash);
            }

            private static SecretKeySpec getPassKey(char[] password) throws Exception {
                byte[] salt = "123456789112345".getBytes();
                PBEKeySpec spec = new PBEKeySpec(password, salt, 600000, 128);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] bytes = factory.generateSecret(spec).getEncoded();
                return new SecretKeySpec(bytes, "AES");
            }

            private static IvParameterSpec generateIv() {
                byte[] iv = new byte[16];
                new SecureRandom().nextBytes(iv);
                return new IvParameterSpec(iv);
            }
        
            private static void addPassword(String mainPassword, String label, String password, Map<String, String> allPasswords) throws Exception {
                SecretKeySpec key = getPassKey(mainPassword.toCharArray());
                IvParameterSpec iv = generateIv();
                String encryption = encryptPassword(password, key, iv);
                allPasswords.put(label, encryption + ":" + Base64.getEncoder().encodeToString(iv.getIV()));
                writeFile(allPasswords);
            }

            private static String readPassword(String mainPassword, String label, Map<String, String> allPasswords) throws Exception {
                if(allPasswords.containsKey(label)) {
                    String[] data = allPasswords.get(label).split(":");
                    String encryption = data[0];
                    byte[] iv = Base64.getDecoder().decode(data[1]);
                    SecretKeySpec key = getPassKey(mainPassword.toCharArray());
                    return decryptPassword(encryption, key, new IvParameterSpec(iv));
                }
                else {
                    return "No password found for that label.";
                }
            }

            private static String encryptPassword(String password, SecretKeySpec key, IvParameterSpec iv) throws Exception {
                Cipher cipher = Cipher.getInstance(PASSWORD_FILE);
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                byte[] encryption = cipher.doFinal(password.getBytes());
                return Base64.getEncoder().encodeToString(encryption);
            }

            private static String decryptPassword(String encryption, SecretKeySpec key, IvParameterSpec iv) throws Exception {
                Cipher cipher = Cipher.getInstance(PASSWORD_FILE);
                cipher.init(Cipher.DECRYPT_MODE, key, iv);
                byte[] decryption = cipher.doFinal(Base64.getDecoder().decode(encryption));
                return new String(decryption);
            }

            private static void writeFile(Map<String, String> allPasswords) throws IOException {
                BufferedWriter fileWriter = new BufferedWriter(new FileWriter(PASSWORD_FILE));
                for(Map.Entry<String, String> entry:allPasswords.entrySet()) {
                    fileWriter.write(entry.getKey() + ":" + entry.getValue());
                    fileWriter.newLine();
                }
                fileWriter.close();
            }


    }

