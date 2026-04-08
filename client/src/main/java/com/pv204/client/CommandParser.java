package com.pv204.client;

public class CommandParser {

    public ClientRequest parse(String[] args) {

        if (args.length == 0) {
            return new ClientRequest("help", null, null, null);
        }

        String command = args[0].toLowerCase();

        switch (command) {

            case "add":
                if (args.length < 4) {
                    throw new IllegalArgumentException("Usage: add <pin> <name> <value>");
                }
                // CORRECT ORDER: (command, name, value, pin)
                return new ClientRequest("add", args[2], args[3], args[1]);

            case "list":
                return new ClientRequest("list", null, null, null);

            case "get":
                if (args.length < 3) {
                    throw new IllegalArgumentException("Usage: get <pin> <name>");
                }
                return new ClientRequest("get", args[2], null, args[1]);

            case "change-pin":
                if (args.length < 3) {
                    throw new IllegalArgumentException("Usage: change-pin <oldPin> <newPin>");
                }
                // store oldPin in name, newPin in value
                return new ClientRequest("change-pin", args[1], args[2], null);

            case "help":
                return new ClientRequest("help", null, null, null);

            default:
                throw new IllegalArgumentException("Unknown command");
        }
    }
}