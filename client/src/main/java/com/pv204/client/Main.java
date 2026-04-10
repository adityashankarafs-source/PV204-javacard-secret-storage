package com.pv204.client;

import java.util.List;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        System.out.println("=== PV204 JavaCard Secret Storage Client ===");
        System.out.println("Type 'help' for commands. Type 'exit' to quit.");

        try {
            CardManager manager = new CardManager();
            Scanner scanner = new Scanner(System.in);

            while (true) {
                System.out.print("> ");
                String line = scanner.nextLine();

                if (line == null) {
                    break;
                }

                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }

                if (line.equalsIgnoreCase("exit") || line.equalsIgnoreCase("quit")) {
                    System.out.println("Exiting...");
                    break;
                }

                try {
                    String[] parts = line.split("\\s+");
                    String cmd = parts[0].toLowerCase();

                    switch (cmd) {
                        case "help":
                            printHelp();
                            break;

                        case "init":
                            if (parts.length != 2) {
                                System.out.println("Usage: init <32-hex-key | 16-char-key>");
                                break;
                            }
                            System.out.println(manager.init(parts[1]));
                            break;

                        case "open":
                            System.out.println(manager.open());
                            break;

                        case "verify":
                            if (parts.length != 2) {
                                System.out.println("Usage: verify <pin>");
                                break;
                            }
                            System.out.println(manager.verify(parts[1]));
                            break;

                        case "store":
                            if (parts.length != 3) {
                                System.out.println("Usage: store <name> <value>");
                                break;
                            }
                            System.out.println(manager.store(parts[1], parts[2]));
                            break;

                        case "list":
                            List<String> secrets = manager.list();
                            if (secrets.isEmpty()) {
                                System.out.println("(no secrets stored)");
                            } else {
                                for (String s : secrets) {
                                    System.out.println("- " + s);
                                }
                            }
                            break;

                        case "get":
                            if (parts.length != 2) {
                                System.out.println("Usage: get <name>");
                                break;
                            }
                            System.out.println(manager.get(parts[1]));
                            break;

                        case "change-pin":
                            if (parts.length != 3) {
                                System.out.println("Usage: change-pin <oldPin> <newPin>");
                                break;
                            }
                            System.out.println(manager.changePin(parts[1], parts[2]));
                            break;

                        default:
                            System.out.println("Unknown command. Type 'help'.");
                    }
                } catch (Exception e) {
                    System.out.println("ERROR: " + e.getMessage());
                }

                System.out.println();
            }

            scanner.close();
        } catch (Exception e) {
            System.out.println("Fatal error: " + e.getMessage());
            e.printStackTrace(System.out);
        }
    }

    private static void printHelp() {
        System.out.println("Commands:");
        System.out.println("  init <32-hex-key | 16-char-key>");
        System.out.println("  open");
        System.out.println("  verify <pin>");
        System.out.println("  store <name> <value>");
        System.out.println("  list");
        System.out.println("  get <name>");
        System.out.println("  change-pin <oldPin> <newPin>");
        System.out.println("  help");
        System.out.println("  exit");
    }
}