package com.pv204.client;

public class Main {
    public static void main(String[] args) {
        System.out.println("PV204 JavaCard Secret Storage Client");

        if (args.length == 0) {
            System.out.println("Usage:");
            System.out.println("  add <name> <value>");
            System.out.println("  list");
            System.out.println("  get <name>");
            System.out.println("  change-pin <oldPin> <newPin>");
            return;
        }

        String command = args[0];
        CardManager cardManager = new CardManager();
        cardManager.connect();

        switch (command) {
            case "add":
                if (args.length < 3) {
                    System.out.println("Usage: add <name> <value>");
                    return;
                }
                System.out.println("Storing secret: " + args[1]);
                cardManager.sendCommand("STORE_SECRET");
                System.out.println("Secret stored successfully (mock output).");
                break;

            case "list":
                System.out.println("Listing secrets...");
                cardManager.sendCommand("LIST_SECRETS");
                System.out.println("- gmail");
                System.out.println("- bank");
                break;

            case "get":
                if (args.length < 2) {
                    System.out.println("Usage: get <name>");
                    return;
                }
                System.out.println("Retrieving secret: " + args[1]);
                cardManager.sendCommand("GET_SECRET");
                System.out.println("Secret value: mock-secret-value");
                break;

            case "change-pin":
                if (args.length < 3) {
                    System.out.println("Usage: change-pin <oldPin> <newPin>");
                    return;
                }
                System.out.println("Changing PIN...");
                cardManager.sendCommand("CHANGE_PIN");
                System.out.println("PIN changed successfully (mock output).");
                break;

            default:
                System.out.println("Unknown command: " + command);
                System.out.println("Available commands: add, list, get, change-pin");
        }
    }
}