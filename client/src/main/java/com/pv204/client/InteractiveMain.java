package com.pv204.client;

import java.util.Scanner;

public class InteractiveMain {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("PV204 Secret Storage Interactive Client");
        System.out.println("Type 'help' for commands.");
        System.out.println("Type 'exit' to quit.");
        System.out.println();

        while (true) {
            System.out.print("client> ");
            String line = scanner.nextLine();

            if (line == null) {
                break;
            }

            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }

            if (line.equalsIgnoreCase("exit") || line.equalsIgnoreCase("quit")) {
                System.out.println("Exiting client.");
                break;
            }

            try {
                String[] cmdArgs = line.split("\\s+");
                Main.main(cmdArgs);
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                e.printStackTrace(System.out);
            }

            System.out.println();
        }

        scanner.close();
    }
}