Library is used in Embedded System to connect to Goldeneye Hubs System.

## Requirement
1. This library is used for microcontroller ESP with Arduino framework.

2. You should use [VSCode](https://code.visualstudio.com/) + [PlatformIO](https://platformio.org/) for development.

## Install
1. Download `gsc-services.json` from here (comming soon).

2. Copy `gsc-services.json` to folder `data` in your project PlatformIO (create folder `data` if it is not existed).

3. Run command: `pio install GSCMbedLib`.

## Note
After running command `pio install GSCMbedLib`, PlatformIO will install GSCMbedLib and dependencies into your project.

## Dependencies
- [ArduinoJSON](https://github.com/bblanchon/ArduinoJson) - 6.12.0
- [Nanopb](https://github.com/nanopb/nanopb) - 0.3.9.2
