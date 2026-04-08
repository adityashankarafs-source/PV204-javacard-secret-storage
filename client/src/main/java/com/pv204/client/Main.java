package com.pv204.client;

import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        System.out.println("=== PV204 JavaCard Secret Storage Client ===");

        CardManager manager = new CardManager();
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.print("> ");
            String line = scanner.nextLine();

            if (line.equalsIgnoreCase("exit")) {
                System.out.println("Exiting...");
                break;
            }

            try {
                String[] input = line.split(" ");
                CommandParser parser = new CommandParser();
                ClientRequest request = parser.parse(input);

                ClientResponse response = manager.handle(request);

                if (!response.isSuccess()) {
                    System.out.println("ERROR: " + response.getMessage());
                    continue;
                }

                System.out.println(response.getMessage());

                if (response.getData() != null) {
                    for (String s : response.getData()) {
                        System.out.println("- " + s);
                    }
                }

            } catch (Exception e) {
                System.out.println("ERROR: " + e.getMessage());
            }
        }
    }
}