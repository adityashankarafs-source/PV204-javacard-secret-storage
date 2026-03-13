package com.pv204.client;

import java.util.List;

public class Main {

    public static void main(String[] args) {

        System.out.println("PV204 JavaCard Secret Storage Client");

        if (args.length == 0) {
            printUsage();
            return;
        }

        CommandParser parser = new CommandParser();
        ClientRequest request = parser.parse(args);

        System.out.println("Connecting to JavaCard simulator...");

        CardManager cardManager = new CardManager(new MockCardBackend());

        ClientResponse response = cardManager.handle(request);

        if (response.getData() != null) {

            System.out.println(response.getMessage());

            for (String s : response.getData()) {
                System.out.println("- " + s);
            }

        } else {
            System.out.println(response.getMessage());
        }
    }

    private static void printUsage() {

        System.out.println("Usage:");
        System.out.println("  add <name> <value>");
        System.out.println("  list");
        System.out.println("  get <name>");
        System.out.println("  change-pin <oldPin> <newPin>");
    }
}