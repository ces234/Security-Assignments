import java.util.Scanner;

public class Main {
    public static void main(String[] args){
        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter the passcode to access your passwords: ");
        String passcode = scanner.nextLine();
        System.out.println(passcode);
    }
}
