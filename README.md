Library is used in Embedded System to connect to Goldeneye Hubs System.

## Requirement
1. This library is used for microcontroller ESP with Arduino framework.

2. You should use [VSCode](https://code.visualstudio.com/) + [PlatformIO](https://platformio.org/) for development.

3. Only using gsc-mbed version >= 2.2.0

## Install
1. Download `gsc-services.json` from here (comming soon).

2. Copy `gsc-services.json` to folder `data` in your project PlatformIO (create folder `data` if it is not existed).

3. Run command: `pio install GSCMbedLib`.

4. In file `pb.h` of dependency Nanopb
```c++
// Uncomment this line
#define PB_FIELD_16BIT 1

// Add this line 
#define PB_WITHOUT_64BIT 1
```

## Note
After running command `pio install GSCMbedLib`, PlatformIO will install GSCMbedLib and dependencies into your project.

## Dependencies
- [ArduinoJSON by Benoit Blanchon](https://github.com/bblanchon/ArduinoJson) - 6.12.0
- [Nanopb by Petteri Aimonen](https://github.com/nanopb/nanopb) - 0.3.9.2
- [BigNumber by NickGammon](https://github.com/nickgammon/BigNumber) - 3.5
- [Crypto by Chris Ellis](https://github.com/intrbiz/arduino-crypto) - 1.0.0
