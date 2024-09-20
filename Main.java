import java.util.Scanner;

public class Main {
    public static void main(String[] args){
        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter the passcode to access your passwords: ");
        String passcode = scanner.nextLine();
        System.out.println(passcode);
    
        while(true) {
            System.out.println("Do you want to add a password(A), read a password(R), or quit(Q)");
            String function = scanner.nextLine();
            if(function.equals("A")) {
                System.out.println("(A): Add a Password");
                System.out.println("Please provide a password label:");
                String label = scanner.nextLine();
                System.out.println("Please provide a password:");
                String password = String password = scanner.nextLine();
                // add password here
            }
            else if(function.equals("R")) {
                System.out.println("(R): Read a Password");
                System.out.println("Enter the label of the password you would like to see:");
                String label = scanner.nextLine();
                // read out password
        }
            else if(function.equals("Q")) {
                System.out.println("Quitting Manager...");
                System.exit(0);
            }
            else {
                System.out.println("Not a valid command.");
            }
        }
    }
}
