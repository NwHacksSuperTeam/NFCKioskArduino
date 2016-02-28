// Modified from https://github.com/miguelbalboa/rfid/blob/master/examples/ReadAndWrite/ReadAndWrite.ino

#include <SPI.h>
#include <MFRC522.h>                // Search for and install MFRC522 by GithubCommunity in the Arduino libraries

#define RST_PIN         9           // Configurable, see typical pin layout above
#define SS_PIN          10          // Configurable, see typical pin layout above
#define NUM_SECTORS     2           // Number of writeable sectors
#define NUM_BLOCKS      3           // Number of writeable blocks per sector

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.
MFRC522::MIFARE_Key key;

byte sectors[] = { 2, 3 };          // Writeable sectors
byte blockAddrs[] = { 8, 9, 10,
                      12, 13, 14 }; // Writeable blocks
byte trailerBlocks[] = { 11, 15 };  // Trailer blocks of each sector
byte dataBlocks[][16]    = {        // Contains the UUID
    { 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x10, 0x00,
      0x08, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
      0x80, 0x80, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
      0x80, 0x80, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb },
    { 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x10, 0x00,
      0x08, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
      0x80, 0x80, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
      0x80, 0x80, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb } };

/**
 * Initialize.
 */
void setup() {
    Serial.begin(9600); // Initialize serial communications with the PC
    while (!Serial);    // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
    SPI.begin();        // Init SPI bus
    mfrc522.PCD_Init(); // Init MFRC522 card

    // Prepare the key (used both as key A and as key B)
    // using FFFFFFFFFFFFh which is the default at chip delivery from the factory
    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF;
    }

    Serial.println(F("Scan a MIFARE Classic PICC to demonstrate read and write."));
    Serial.print(F("Using key (for A and B):"));
    dump_byte_array(key.keyByte, MFRC522::MF_KEY_SIZE);
    Serial.println();
    
    Serial.println(F("BEWARE: Data will be written to the PICC, in sector #1"));
}

/**
 * Main loop.
 */
void loop() {
    // Look for new cards
    if ( ! mfrc522.PICC_IsNewCardPresent())
        return;

    // Select one of the cards
    if ( ! mfrc522.PICC_ReadCardSerial())
        return;

    // Show some details of the PICC (that is: the tag/card)
    Serial.print(F("Card UID:"));
    dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
    Serial.println();
    Serial.print(F("PICC type: "));
    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    Serial.println(mfrc522.PICC_GetTypeName(piccType));

    // Check for compatibility
    if (    piccType != MFRC522::PICC_TYPE_MIFARE_MINI
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
        Serial.println(F("This sample only works with MIFARE Classic cards."));
        return;
    }
    
    MFRC522::StatusCode status;
    byte buffer[18];
    byte size = sizeof(buffer);

    for (unsigned i=0; i < NUM_SECTORS; i++) {
        // Authenticate using key A
        Serial.println(F("Authenticating using key A..."));
        status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlocks[i], &key, &(mfrc522.uid));
        if (status != MFRC522::STATUS_OK) {
            Serial.print(F("PCD_Authenticate() failed: "));
            Serial.println(mfrc522.GetStatusCodeName(status));
            return;
        }
        
        // Show the whole sector as it currently is
        Serial.println(F("Current data in sector:"));
        mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sectors[i]);
        Serial.println();
    
        // Authenticate using key B
        Serial.println(F("Authenticating again using key B..."));
        status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlocks[i], &key, &(mfrc522.uid));
        if (status != MFRC522::STATUS_OK) {
            Serial.print(F("PCD_Authenticate() failed: "));
            Serial.println(mfrc522.GetStatusCodeName(status));
            return;
        }
          
        for (unsigned j=0; j < NUM_BLOCKS; j++) {
            // Write data to the block
            Serial.print(F("Writing data into block ")); Serial.print(blockAddrs[i*NUM_BLOCKS+j]);
            Serial.println(F(" ..."));
            dump_byte_array(dataBlocks[i*NUM_BLOCKS+j], 16); Serial.println();
            status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(blockAddrs[i*NUM_BLOCKS+j], dataBlocks[i*NUM_BLOCKS+j], 16);
            if (status != MFRC522::STATUS_OK) {
                Serial.print(F("MIFARE_Write() failed: "));
                Serial.println(mfrc522.GetStatusCodeName(status));
            }
            Serial.println();
        
            // Read data from the block (again, should now be what we have written)
            Serial.print(F("Reading data from block ")); Serial.print(blockAddrs[i*NUM_BLOCKS+j]);
            Serial.println(F(" ..."));
            status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddrs[i*NUM_BLOCKS+j], buffer, &size);
            if (status != MFRC522::STATUS_OK) {
                Serial.print(F("MIFARE_Read() failed: "));
                Serial.println(mfrc522.GetStatusCodeName(status));
            }
            Serial.print(F("Data in block ")); Serial.print(blockAddrs[i*NUM_BLOCKS+j]); Serial.println(F(":"));
            dump_byte_array(buffer, 16); Serial.println();
                
            // Check that data in block is what we have written
            // by counting the number of bytes that are equal
            Serial.println(F("Checking result..."));
            byte count = 0;
            for (byte k = 0; k < 16; k++) {
                // Compare buffer (= what we've read) with dataBlock (= what we've written)
                if (buffer[k] == dataBlocks[i*NUM_BLOCKS+j][k])
                    count++;
            }
            Serial.print(F("Number of bytes that match = ")); Serial.println(count);
            if (count == 16) {
                Serial.println(F("Success :-)"));
            } else {
                Serial.println(F("Failure, no match :-("));
                Serial.println(F("  perhaps the write didn't work properly..."));
            }
            Serial.println();
                
            // Dump the sector data
            Serial.println(F("Current data in sector:"));
            mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sectors[i]);
            Serial.println();
          }
    }
    
    // Halt PICC
    mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    mfrc522.PCD_StopCrypto1();
}

/**
 * Helper routine to dump a byte array as hex values to Serial.
 */
void dump_byte_array(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}

