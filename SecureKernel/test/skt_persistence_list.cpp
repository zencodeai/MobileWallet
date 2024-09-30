#include <iostream>
#include <map>
#include <list>
#include <memory>

#include "skt_utils.hpp"
#include "sk_persistence.hpp"

// Test persistence class (list)
class SKTTestPersistenceList : public SKTTestCrypto {

private:

    // DB key size
    static const uint32_t DB_KEY_SIZE = (SK_DB_TEST_HEAD_VAL_SIZE - 1);

    // Generate db key (avoid collisions)
    void GenerateDBKey(SKBinaryBuffer& db_key) {

        static const char choices[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
        do {
            // Generate random key
            GenerateRandomData(DB_KEY_SIZE + 1, db_key);

            uint8_t* p = db_key.GetBuffer();
            *p = 'N' + ((*p) % ('Z' - 'N' + 1));
            p ++;

            for (uint32_t i = 1; i < DB_KEY_SIZE; ++i, ++p) {

                *p = choices[(*p) % (sizeof(choices) - 1)];        
            }

            // Null terminate
            *p = 0;
        }
        while (spstore->HasKey(db_key));

        // Update size, exclude null terminator
        db_key.UpdateSize(DB_KEY_SIZE);
    }
    
    // Record structure
    class Record {

    public:

        // Data value db key
        SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_data_val;

        // Data tag value db key
        SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_data_tag;

        // Data
        SKDynamicBinaryBuffer data;

        // Constructor
        Record() {}

        // Destructor
        ~Record() {}
    };

    // Record shared pointer
    typedef std::shared_ptr<class SKTTestPersistenceList::Record> RecordPtr;

    // Create record
    RecordPtr CreateRecord(const SKStoreCryptoKeyPtr& spkey) {

        // Create record
        RecordPtr sprecord(new Record());

        // Generate data value db key
        GenerateDBKey(sprecord->db_key_data_val);

        // Generate data tag db key
        GenerateDBKey(sprecord->db_key_data_tag);

        // Generate random data
        GenerateRandomData(GenerateRandomInt(256, 1024) & 0xFFF0, sprecord->data);

        // Store data and tag
        SKStoreValuePtr spvalue = SKStoreValue::Store(*spstore, spkey, sprecord->db_key_data_val, sprecord->db_key_data_tag, sprecord->data);

        // Return record
        return sprecord;
    }

    // Records
    std::list<RecordPtr> m_records;

    // Run test
    virtual void RunTest();

};

// Run test
void SKTTestPersistenceList::RunTest() {

    // Execute 100 times
    for (int i = 0; i < 10; ++i) {

        // Clear list
        m_records.clear();

        // Generate key
        SKCrypto::SKKeyId key_id;
        spcrypto->AES128GCMGenerateKey(key_id);

        // Store key
        SKStoreKey<SK_DB_TEST_SYM_SIZE> db_key_id(SK_DB_TEST_SYM_HEX);
        SKStoreCryptoKeyPtr spkey = SKStoreCryptoKey::Store(*spstore, spcrypto, key_id, db_key_id);

        // Create records
        for (int j = 0; j < 100; ++j) {

            // Create record
            RecordPtr sprecord = CreateRecord(spkey);

            // Store record
            m_records.push_back(sprecord);
        }

        // Initialize list
        SKStoreList list(spstore, sprandom, spkey);

        // Iterate through records
        std::list<RecordPtr>::iterator it = m_records.begin();
        list.Initialize(SK_DB_TEST_HEAD_VAL, SK_DB_TEST_HEAD_TAG, (*it)->db_key_data_val, (*it)->db_key_data_tag);
        ++it;
        while (it != m_records.end()) {

            // Get record
            RecordPtr sprecord = *it;

            list.Add(sprecord->db_key_data_val, sprecord->db_key_data_tag);

            // Next record
            ++it;
        }

        // Verify list
        it = m_records.begin();
        list.Start(SK_DB_TEST_HEAD_VAL, SK_DB_TEST_HEAD_TAG);

        while (it != m_records.end()) {

            // Get record
            RecordPtr sprecord = *(it ++);

            SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_data_val;
            SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_data_tag;

            SKStoreValuePtr spnode = list.Next(db_key_data_val, db_key_data_tag);
            SK_CHECK((it == m_records.end() ? !spnode : (bool)(spnode)), SK_ERROR_FAILED, "List end or records end not reached");

            // Load record data
            SKStoreValuePtr spdata = SKStoreValue::Load(*spstore, spkey, db_key_data_val, db_key_data_tag);

            // Verify data
            SKDynamicBinaryBuffer plain;
            spdata->Decrypt(plain);

            // Verify data
            SK_CHECK(plain == sprecord->data, SK_ERROR_FAILED, "Data mismatch");
        }
        
        // Delete list
        list.Delete(SK_DB_TEST_HEAD_VAL, SK_DB_TEST_HEAD_TAG);

        // Verify that records are deleted
        it = m_records.begin();
        while (it != m_records.end()) {

            // Get record
            RecordPtr sprecord = *it;

            // No data
            SK_CHECK(!spstore->HasKey(sprecord->db_key_data_val), SK_ERROR_FAILED, "Data not deleted");

            // No tag
            SK_CHECK(!spstore->HasKey(sprecord->db_key_data_tag), SK_ERROR_FAILED, "Tag not deleted");

            // Next record
            ++it;
        }

        spcrypto->DeleteKey(key_id);
    }
}

// Entry point.
int test_skt_persistence_list(int, char*[]) {
    
        // Create test
        SKTTestPersistenceList test;
        return test.Run();
}
