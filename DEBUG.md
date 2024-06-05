## How to debug in VSCode

1. Create a directory `.vscode` (probably it already exists) on the top-level workspace directory.

2. There you need to create/edit 2 files: `tasks.json` and `launch.json`

3. Add the following to `tasks.json`:

```json
{
    // See https://go.microsoft.com/fwlink/?LinkId=733558
    // for the documentation about the tasks.json format
    "version": "2.0.0",
    "tasks": [
      {
        "label": "Build initiator",
        "type": "shell",
        "command": "make -j",
        "options": {"cwd": "${workspaceFolder}/samples/linux_edhoc/initiator"},
        "group": {
          "kind": "build",
          "isDefault": true
        },
        "problemMatcher": {
          "owner": "cpp",
          "fileLocation": [
            "relative",
            "${workspaceFolder}/samples/linux_edhoc/initiator"
          ],
          "pattern": {
            "regexp": "^(.*):(\\d+):(\\d+):\\s+(warning|error):\\s+(.*)$",
            "file": 1,
            "line": 2,
            "column": 3,
            "severity": 4,
            "message": 5
          }
        }
      },
      {
        "label": "Build responder",
        "type": "shell",
        "command": "make -j",
        "options": {"cwd": "${workspaceFolder}/samples/linux_edhoc/responder"}, // executable path
        "group": {
          "kind": "build",
          "isDefault": true
        },
        "problemMatcher": {
          "owner": "cpp",
          "fileLocation": [
            "relative",
            "${workspaceFolder}/samples/linux_edhoc/responder"
          ],
          "pattern": {
            "regexp": "^(.*):(\\d+):(\\d+):\\s+(warning|error):\\s+(.*)$",
            "file": 1,
            "line": 2,
            "column": 3,
            "severity": 4,
            "message": 5
          }
        }

      },
      {
        "label": "Build all",
        "type": "shell",
        "command": "echo Hello ",
        "dependsOrder": "sequence",
        "dependsOn": ["Build initiator", "Build responder"]
      }
    ]
  }
```

4. Add the following to `launch.json`:

```json
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [        
        
        {
            "name": "Initiator", 
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/samples/linux_edhoc/initiator/build/initiator", // executable path
            "args": [],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ]
        },
        {
            "name": "Responder", 
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/samples/linux_edhoc/responder/build/responder",
            "args": [],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ] 
        }
    ]
}
```

5. Build the 2 executables (initiator and responder) either by pressing `Ctrl+Shift+B` or by using the terminal

6. Add a breakpoint in the `main.cpp` of `initiator` and you debug by going to `Run > Start Debugging`

7. You can also debug the `initiator` executable from the drop down menu in the Debug view (at top left).