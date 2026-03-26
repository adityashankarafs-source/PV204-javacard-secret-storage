package com.pv204.client;

public class Main {
    public static void main(String[] args) {
        System.out.println("=== PV204 JavaCard Secret Storage Client ===");

        if (args.length == 0) {
            printHelp();
            return;
        }

        String command = args[0].toLowerCase();
        CardManager cardManager = new CardManager();
        cardManager.connect();
        cardManager.openSecureSession();

        switch (command) {
            case "add":
                handleAdd(args, cardManager);
                break;
            case "list":
                handleList(cardManager);
                break;
            case "get":
                handleGet(args, cardManager);
                break;
            case "change-pin":
                handleChangePin(args, cardManager);
                break;
            case "help":
                printHelp();
                break;
            default:
                System.out.println("Unknown command: " + command);
                printHelp();
        }
    }

    private static void handleAdd(String[] args, CardManager cardManager) {
        if (args.length < 3) {
            System.out.println("Usage: add <name> <value>");
            return;
        }

        String name = args[1];
        String value = args[2];

        if (name.length() > 20) {
            System.out.println("Error: name too long");
            return;
        }

        if (value.length() > 50) {
            System.out.println("Error: value too long");
            return;
        }

        System.out.println("Action: Store Secret");
        System.out.println("Secret name: " + name);
        cardManager.sendCommand("STORE_SECRET");
        System.out.println("Result: Secret stored successfully (mock output).");
    }

    private static void handleList(CardManager cardManager) {
        System.out.println("Action: List Secrets");
        cardManager.sendCommand("LIST_SECRETS");
        System.out.println("Stored secrets:");
        System.out.println("- gmail");
        System.out.println("- bank");
    }

    private static void handleGet(String[] args, CardManager cardManager) {
        if (args.length < 2) {
            System.out.println("Usage: get <name>");
            return;
        }

        String name = args[1];
        System.out.println("Action: Get Secret");
        System.out.println("Secret name: " + name);
        cardManager.sendCommand("GET_SECRET");
        System.out.println("Result: Secret value = mock-secret-value");
    }

    private static void handleChangePin(String[] args, CardManager cardManager) {
        if (args.length < 3) {
            System.out.println("Usage: change-pin <oldPin> <newPin>");
            return;
        }

        System.out.println("Action: Change PIN");
        cardManager.sendCommand("CHANGE_PIN");
        System.out.println("Result: PIN changed successfully (mock output).");
    }

    private static void printHelp() {
        System.out.println("Usage:");
        System.out.println("  add <name> <value>");
        System.out.println("  list");
        System.out.println("  get <name>");
        System.out.println("  change-pin <oldPin> <newPin>");
        System.out.println("  help");
    }
}