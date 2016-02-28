/**
 * ----------------------------------------------------------------------------
 * This is a MFRC522 library example; see https://github.com/miguelbalboa/rfid
 * for further details and other examples.
 * 
 * NOTE: The library file MFRC522.h has a lot of useful info. Please read it.
 * 
 * Released into the public domain.
 * ----------------------------------------------------------------------------
 * This sample shows how to read and write data blocks on a MIFARE Classic PICC
 * (= card/tag).
 * 
 * BEWARE: Data will be written to the PICC, in sector #1 (blocks #4 to #7).
 * 
 * 
 * Typical pin layout used:
 * -----------------------------------------------------------------------------------------
 *             MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
 *             Reader/PCD   Uno           Mega      Nano v3    Leonardo/Micro   Pro Micro
 * Signal      Pin          Pin           Pin       Pin        Pin              Pin
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
 * SPI SS      SDA(SS)      10            53        D10        10               10
 * SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
 * SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
 * SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15
 * 
 */

#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN         9           // Configurable, see typical pin layout above
#define SS_PIN          10          // Configurable, see typical pin layout above
#define NUM_SECTORS     3

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

MFRC522::MIFARE_Key key;

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
    
    byte trailerBlock   = 11;
    MFRC522::StatusCode status;
    byte buffer[18];
    byte size = sizeof(buffer);

    // In this sample we use the second sector,
    // that is: sector #1, covering block #4 up to and including block #7
    byte sector         = 2;
    byte blockAddr      = 8;
    byte dataBlock[]    = {
        0x00, 0x00, 0x11, 0x01, //  1,  2,   3,  4,
        0x00, 0x00, 0x10, 0x00, //  5,  6,   7,  8,
        0x08, 0x00, 0x00, 0x80, //  9, 10, 255, 12,
        0x5f, 0x9b, 0x34, 0xfb  // 13, 14,  15, 16
    };
    
    byte dataBlock1[] = {
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x10, 0x00,
      0x80, 0x80, 0x00, 0x80, 
      0x5f, 0x9b, 0x34, 0xfb
    };
    
    byte dataBlock2[] = {
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x10, 0x00,
      0x80, 0x80, 0x00, 0x80, 
      0x5f, 0x9b, 0x34, 0xfb    
    };
    
    byte dataBlock3[] = {
        0x00, 0x00, 0x11, 0x01, //  1,  2,   3,  4,
        0x00, 0x00, 0x10, 0x00, //  5,  6,   7,  8,
        0x08, 0x00, 0x00, 0x80, //  9, 10, 255, 12,
        0x5f, 0x9b, 0x34, 0xfb  // 13, 14,  15, 16
    };
    
    byte dataBlock4[] = {
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x10, 0x00,
      0x80, 0x80, 0x00, 0x80, 
      0x5f, 0x9b, 0x34, 0xfb
    };
    
    byte dataBlock5[] = {
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x10, 0x00,
      0x80, 0x80, 0x00, 0x80, 
      0x5f, 0x9b, 0x34, 0xfb
    };
    
    byte blockAddresses2[] = {8, 9, 10,};
    
    byte *dataBlocks[] = {dataBlock, dataBlock1, dataBlock2};
    
    
    // Authenticate using key A
    Serial.println(F("Authenticating using key A..."));
    status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }
    

    // Show the whole sector as it currently is
    Serial.println(F("Current data in sector:"));
    mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
    Serial.println();

    // Read data from the block
    Serial.print(F("Reading data from block ")); Serial.print(blockAddr);
    Serial.println(F(" ..."));
    status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
    }
    Serial.print(F("Data in block ")); Serial.print(blockAddr); Serial.println(F(":"));
    dump_byte_array(buffer, 16); Serial.println();
    Serial.println();

    // Authenticate using key B
    Serial.println(F("Authenticating again using key B..."));
    status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    for (unsigned i=0; i<NUM_SECTORS; i++) {
      // Write data to the block
      Serial.print(F("Writing data into block ")); Serial.print(blockAddresses2[i]);
      Serial.println(F(" ..."));
      dump_byte_array(dataBlocks[i], 16); Serial.println();
      status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(blockAddresses2[i], dataBlocks[i], 16);
      if (status != MFRC522::STATUS_OK) {
          Serial.print(F("MIFARE_Write() failed: "));
          Serial.println(mfrc522.GetStatusCodeName(status));
      }
      Serial.println();
  
      // Read data from the block (again, should now be what we have written)
      Serial.print(F("Reading data from block ")); Serial.print(blockAddresses2[i]);
      Serial.println(F(" ..."));
      status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddresses2[i], buffer, &size);
      if (status != MFRC522::STATUS_OK) {
          Serial.print(F("MIFARE_Read() failed: "));
          Serial.println(mfrc522.GetStatusCodeName(status));
      }
      Serial.print(F("Data in block ")); Serial.print(blockAddresses2[i]); Serial.println(F(":"));
      dump_byte_array(buffer, 16); Serial.println();
          
      // Check that data in block is what we have written
      // by counting the number of bytes that are equal
      Serial.println(F("Checking result..."));
      byte count = 0;
      for (byte j = 0; j < 16; j++) {
          // Compare buffer (= what we've read) with dataBlock (= what we've written)
          if (buffer[j] == dataBlocks[i][j])
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
      mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
      Serial.println();
    }
    
    // -----------------------
    
    // Authenticate using key A
    Serial.println(F("Authenticating using key A..."));
    status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock+4, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }
    

    // Show the whole sector as it currently is
    Serial.println(F("Current data in sector:"));
    mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
    Serial.println();

    // Read data from the block
    Serial.print(F("Reading data from block ")); Serial.print(blockAddr);
    Serial.println(F(" ..."));
    status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
    }
    Serial.print(F("Data in block ")); Serial.print(blockAddr); Serial.println(F(":"));
    dump_byte_array(buffer, 16); Serial.println();
    Serial.println();

    // Authenticate using key B
    Serial.println(F("Authenticating again using key B..."));
    status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock+4, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }
    
    byte blockAddresses3[] = {12,13,14};
    
    byte *dataBlocks3[] = {dataBlock3, dataBlock4, dataBlock5};
    
    for (unsigned i=0; i<NUM_SECTORS; i++) {
      // Write data to the block
      Serial.print(F("Writing data into block ")); Serial.print(blockAddresses3[i]);
      Serial.println(F(" ..."));
      dump_byte_array(dataBlocks3[i], 16); Serial.println();
      status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(blockAddresses3[i], dataBlocks3[i], 16);
      if (status != MFRC522::STATUS_OK) {
          Serial.print(F("MIFARE_Write() failed: "));
          Serial.println(mfrc522.GetStatusCodeName(status));
      }
      Serial.println();
  
      // Read data from the block (again, should now be what we have written)
      Serial.print(F("Reading data from block ")); Serial.print(blockAddresses3[i]);
      Serial.println(F(" ..."));
      status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddresses3[i], buffer, &size);
      if (status != MFRC522::STATUS_OK) {
          Serial.print(F("MIFARE_Read() failed: "));
          Serial.println(mfrc522.GetStatusCodeName(status));
      }
      Serial.print(F("Data in block ")); Serial.print(blockAddresses3[i]); Serial.println(F(":"));
      dump_byte_array(buffer, 16); Serial.println();
          
      // Check that data in block is what we have written
      // by counting the number of bytes that are equal
      Serial.println(F("Checking result..."));
      byte count = 0;
      for (byte j = 0; j < 16; j++) {
          // Compare buffer (= what we've read) with dataBlock (= what we've written)
          if (buffer[j] == dataBlocks3[i][j])
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
      mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector+1);
      Serial.println();
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

