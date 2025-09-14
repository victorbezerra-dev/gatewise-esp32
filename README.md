GateWise – ESP32 Module
========================

<p align="center">
  <img src="https://github.com/user-attachments/assets/598b43d3-f646-415c-b839-3a20e986bd4a" alt="Lock Photo" width="30%"/>
  <img src="https://github.com/user-attachments/assets/b42ceb9e-f30b-454d-877d-3acafbe3890d" alt="Lock Photo 2" width="30%"/>
</p>



This repository contains the firmware for the ESP32 that controls the smart lock in the GateWise ecosystem.
The project is structured around 4 main modules:

1. ESP32 (this repo) → Handles the physical lock, Wi-Fi/MQTT/HTTP connectivity, RSA signature verification, and lock actuation.
2. Mobile App → End-user app to request access and check logs.
3. Backend (.NET + Keycloak + RabbitMQ) → Handles authentication, issues signed commands, and manages business rules.
4. Web Dashboard → Admin panel for managing labs, users, and access history.

What this module does
---------------------
- Connects the ESP32 to Wi-Fi and to the MQTT broker.
- Listens for lock commands published on a specific topic.
- Verifies the RSA signature (SHA-256) of each command to ensure authenticity.
- If the signature is valid, sends an HTTP confirmation back to the backend.
- Once the backend confirms, triggers the lock pin for a few seconds to unlock.
- Uses an LED to indicate internet status (off = disconnected, blinking = no internet, on = internet OK).

Hardware
--------
- ESP32 DevKit board
- Relay/driver connected to the lock
- Status LED (internet state)

Default pins (adjust if needed):
- Lock relay: GPIO 21
- Internet LED: GPIO 15

Software stack
--------------
- Arduino Core for ESP32 (C++)
- WiFi.h → Wi-Fi connection
- PubSubClient → MQTT client
- ArduinoJson → JSON parsing
- mbedTLS → RSA sign/verify + Base64
- HTTPClient → Send confirmation requests to backend

Security flow
-------------
1. Backend issues a command (open) and signs it with its private key.
2. ESP32 receives the message via MQTT and validates the signature using the backend’s public key stored in the firmware.
3. ESP32 sends an HTTP confirmation with its own signature to the backend.
4. Only if the backend acknowledges, the ESP32 drives the lock pin.

Repo structure
--------------
```
gatewise-esp32/
├─ gatewise_lock_controller_esp32.cpp   # Main firmware file
└─ README.txt
```
Running
-------
1. Configure your Wi-Fi and MQTT broker credentials inside the code.
2. Upload the firmware to your ESP32 (Arduino IDE or PlatformIO).
3. Connect the relay to the lock and test with a signed command.
## Authentication and Access Control Flow
<img width="1436" height="1447" alt="gatewise-flow" src="https://github.com/user-attachments/assets/e22b1d1d-3911-44f4-9445-a3e12f3fe69f" />


Next steps
----------
- Add OTA updates
- Improve telemetry (RSSI, uptime, error counters)
- Support multiple lock channels on the same device
- Persist nonce history to flash for stronger replay protection

License
-------
This project is licensed under the MIT License – see the LICENSE file for details.
