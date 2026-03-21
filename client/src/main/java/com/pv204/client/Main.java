package com.pv204.client;

public class Main {
    public static void main(String[] args) {
        System.out.println("PV204 JavaCard Secret Storage Client");

        if (args.length == 0) {
            printUsage();
            return;
        }

        try {
            CommandParser parser = new CommandParser();
            ClientRequest request = parser.parse(args);
            if ("help".equals(request.getCommand())) {
                printUsage();
                return;
            }

            CardManager cardManager = new CardManager();
            ClientResponse response = cardManager.handle(request);

            if (!response.isSuccess()) {
                System.out.println("ERROR: " + response.getMessage());
                return;
            }

            System.out.println(response.getMessage());
            if (response.getData() != null) {
                for (String value : response.getData()) {
                    System.out.println("- " + value);
                }
            }
        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
        }
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  add <pin> <name> <value>");
        System.out.println("  list");
        System.out.println("  get <pin> <name>");
        System.out.println("  change-pin <oldPin> <newPin>");
    }
}
