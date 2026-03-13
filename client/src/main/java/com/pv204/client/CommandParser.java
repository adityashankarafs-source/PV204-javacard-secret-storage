package com.pv204.client;

public class CommandParser {

    public ClientRequest parse(String[] args) {

        if (args.length == 0) {
            return new ClientRequest("help", null, null, null);
        }

        String command = args[0];

        switch (command) {

            case "add":
                if (args.length < 3) {
                    throw new IllegalArgumentException("Usage: add <name> <value>");
                }
                return new ClientRequest("add", args[1], args[2], null);

            case "list":
                return new ClientRequest("list", null, null, null);

            case "get":
                if (args.length < 2) {
                    throw new IllegalArgumentException("Usage: get <name>");
                }
                return new ClientRequest("get", args[1], null, null);

            case "change-pin":
                if (args.length < 3) {
                    throw new IllegalArgumentException("Usage: change-pin <oldPin> <newPin>");
                }
                return new ClientRequest("change-pin", null, args[1], args[2]);

            default:
                return new ClientRequest("help", null, null, null);
        }
    }
}