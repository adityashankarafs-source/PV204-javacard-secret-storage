package com.pv204.client;

public class CommandParser {
    public ClientRequest parse(String[] args) {
        if (args.length == 0) {
            return new ClientRequest("help", null, null, null);
        }

        String command = args[0];
        switch (command) {
            case Commands.ADD:
                if (args.length < 4) {
                    throw new IllegalArgumentException("Usage: add <pin> <name> <value>");
                }
                return new ClientRequest(Commands.ADD, args[2], args[3], args[1]);
            case Commands.LIST:
                return new ClientRequest(Commands.LIST, null, null, null);
            case Commands.GET:
                if (args.length < 3) {
                    throw new IllegalArgumentException("Usage: get <pin> <name>");
                }
                return new ClientRequest(Commands.GET, args[2], null, args[1]);
            case Commands.CHANGE_PIN:
                if (args.length < 3) {
                    throw new IllegalArgumentException("Usage: change-pin <oldPin> <newPin>");
                }
                return new ClientRequest(Commands.CHANGE_PIN, null, args[1], args[2]);
            default:
                return new ClientRequest("help", null, null, null);
        }
    }
}
