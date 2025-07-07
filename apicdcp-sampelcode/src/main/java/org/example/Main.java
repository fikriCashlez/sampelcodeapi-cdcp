package org.example;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static org.example.RSAUtil.*;

public class Main {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static final char[] HEX = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    private static String URL = "https://octopus-decoupling.cashlez.com/"; //TODO: BASE URL

    private static String amountKSN;
    private static String amountIpek;
    private static String generalIpek;
    private static String generalKsn;

    private static String emvKSN;
    private static String emvIPEK;
    private static String pinIPEK;
    private static String pinKSN;
    private static String trackKSN;
    private static String trackIPEK;

    private static String token;
    private static String sAmountKsnIndex;
    private static String sAmountKsn;
    private static String sAmountEnc;
    private static String sAmountSHA512;

    private static String sEmvKsnIndex;
    private static String sEmvKsn;
    private static String sEmvEnc;
    private static int sEmvLength;

    private static String sTrack2KsnIndex;
    private static String sTrack2Ksn;
    private static String sTrackEnc;
    private static int sTrackLength;
    private static String sTrackSHA512;

    private static String sPinKsnIndex;
    private static String sPinKsn;
    private static String sPinEnc;
    private static int sPinLength;

    private static String privateKey;
    private static String publicKey;

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        //TODO: 1. Function to handle login process
        doLogin();

        //TODO Amount
        generateEncAmount(555);

        encEmvData("820254008407A0000006021010950542000400009A032507079C01005F2A0203605F3401019F02060000000555009F03060000000000009F101C9F01A00000000011BB4E5000000000000000000000000000000000009F1A0203609F26081312F12BCABA6C949F2701809F3303E040C89F34030200009F3501229F360201539F3704163579479F0607A000000602101050104E53494343532041544D2F44656269749F12064E53494343539B02E8005F280203609F15020000");

        //TODO track2 data
        encTrack2Data("5221845000122846D28082260000071900000F");

        //TODO PINBlock data
        encPinData("06122C13FFFEDD7B");

        doSaleTrx();
    }

    private static void doLogin() {
        String endPoint = URL + "MmCorePsgsHost/v1/login";

        String username = "ittest02";
        long timestamp = getCurrentTimestamp();
        String passwrdMd5 = encryptByMD5("123456");
        String timeStamp = String.valueOf(timestamp);
        String pasHas256 = encryptBySHA256(timeStamp + passwrdMd5);

        OkHttpClient client = new OkHttpClient();
        // Buat JSON body
        Map<String, Object> jsonBody = new HashMap<>();
        jsonBody.put("device_timestamp", timeStamp);
        jsonBody.put("isVisibleUsername", false);
        jsonBody.put("pass_hash", pasHas256);
        jsonBody.put("username", username);

        String json = new Gson().toJson(jsonBody);

        RequestBody requestBody = RequestBody.create(
                json,
                MediaType.parse("application/json")
        );

        Request request = new Request.Builder()
                .url(endPoint)
                .post(requestBody)
                .addHeader("Content-Type", "application/json")
                .addHeader("hit-from", "rest-1751866232-AWSA1FAV") //TODO format {Prefix}-{device_timestamp}-{random 8 alphanumeric}
                .build();

        try (Response response = client.newCall(request).execute()) {
            System.out.println("------------------------Data Plain Login Request-------------------------------------");
            System.out.println("Username---------------------: " + username);
            System.out.println("device_timestamp-------------: " + timeStamp);
            System.out.println("pass_hash--------------------: " + pasHas256);
            System.out.println("-------------------------Login Process-----------------------------------------------");
            System.out.println("URL path Login-----------:" + request.url().url().getPath());
            System.out.println("Request body-------------:\n" + json);
            System.out.println("Status code--------------: " + response.code());

            String responseBody = response.body().string();
            System.out.println("Response body------------:\n" + responseBody);

            // Parsing JSON untuk ambil token
            JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();
            if ("0000".equals(jsonObject.get("response_code").getAsString())) {
                if (jsonObject.has("token")) {
                    token = jsonObject.get("token").getAsString();
                    System.out.println("✅Token Login------------: " + token);

                    //TODO: 2. get_general_device_key & get_cdcp_device_key service
                    generateRSAPublicPrivateKey();
                    doGetCDCPKey();
                    doGetGeneralKey();

                } else {
                    System.out.println("⚠️Token not found on response.");
                }
            } else {
                String message = jsonObject.get("message").getAsString();
                System.out.println("❌Login failed: " + message);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void generateRSAPublicPrivateKey() {
        Map<String, Object> keyMap = null;
        try {
            keyMap = RSAUtil.initKey();
            publicKey = getPublicKey(keyMap).trim(); //TODO The public key is sent in the request body of the get_general_device_key service.
            privateKey = getPrivateKey(keyMap).trim(); //TODO: Store the private key for decrypting the response data (amountKSN, amountIpek, generalIpek, generalKSN) from the get_general_device_key service.

            System.out.println("----------------------------RSA PublicKey & PrivateKey-------------------------------");
            System.out.println("Public KEY--------------: " + publicKey.trim());
            System.out.println("PRIVATE KEY-------------: " + privateKey.trim());

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static void doGetGeneralKey() {

        //TODO: URL
        String endPoint = URL + "MmCorePsgsHost/v1/get_general_device_key";

        long timestamp = getCurrentTimestamp();
        OkHttpClient client = new OkHttpClient();
        // Buat JSON body generalDeviceKey
        Map<String, Object> jsonBody = new HashMap<>();
        jsonBody.put("device_timestamp", timestamp);
        jsonBody.put("device_id", "PB10211W21557"); //TODO: Replace with the serial number (SN) of the device you are using.
        jsonBody.put("pub_key", publicKey.trim());


        String json = new Gson().toJson(jsonBody);

        RequestBody requestBody = RequestBody.create(
                json,
                MediaType.parse("application/json")
        );

        Request request = new Request.Builder()
                .url(endPoint)
                .post(requestBody)
                .addHeader("Content-Type", "application/json")
                .addHeader("Authorization", token)
                .addHeader("hit-from", "rest-1751866232-AWSA1FAV") //TODO format {Prefix}-{device_timestamp}-{random 8 alphanumeric}
                .build();

        try (Response response = client.newCall(request).execute()) {
            System.out.println("-------------------------Process get_general_device_key--------------------------");
            System.out.println("URL path generalDeviceKey-----------------:" + request.url().url().getPath());
            System.out.println("Request body------------------------------:\n" + json);
            System.out.println("Status code-------------------------------: " + response.code());

            String responseBody = response.body().string();
            System.out.println("Response body-----------------------------:\n" + responseBody);

            // Parsing JSON
            JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();

            // get object "enc_keys"
            JsonObject encKeys = jsonObject.getAsJsonObject("enc_keys");

            if (encKeys != null) {
                String amountKsn = encKeys.get("amount_ksn").getAsString();
                String amountIpek = encKeys.get("amount_ipek").getAsString();
                String generalKsn = encKeys.get("general_ksn").getAsString();
                String generalIpek = encKeys.get("general_ipek").getAsString();

                //TODO: Use the private key to decrypt the data: AmountKSN, AmountIpek, GeneralIpek, and GeneralKSN
                decryptedGeneralKeyWithPrivateKey(amountKsn, amountIpek, generalIpek, generalKsn, privateKey);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void doGetCDCPKey() {

        //TODO: URL
        String endPoint = URL + "MmCoreCdcpHost/v1/get_cdcp_device_key";

        long timestamp = getCurrentTimestamp();
        OkHttpClient client = new OkHttpClient();
        // Buat JSON body doGetCDCPKey
        Map<String, Object> jsonBody = new HashMap<>();
        jsonBody.put("device_timestamp", timestamp);
        jsonBody.put("device_id", "PB10211W21557"); //TODO: Replace with the serial number (SN) of the device you are using.
        jsonBody.put("pub_key", publicKey.trim());


        String json = new Gson().toJson(jsonBody);

        RequestBody requestBody = RequestBody.create(
                json,
                MediaType.parse("application/json")
        );

        Request request = new Request.Builder()
                .url(endPoint)
                .post(requestBody)
                .addHeader("Content-Type", "application/json")
                .addHeader("Authorization", token)
                .addHeader("hit-from", "rest-1751866232-AWSA1FAV") //TODO format {Prefix}-{device_timestamp}-{random 8 alphanumeric}
                .build();

        try (Response response = client.newCall(request).execute()) {
            System.out.println("-------------------------Process get_cdcp_device_key--------------------------");
            System.out.println("URL path CDCPKey-----------------:" + request.url().url().getPath());
            System.out.println("Request body------------------------------:\n" + json);
            System.out.println("Status code-------------------------------: " + response.code());

            String responseBody = response.body().string();
            System.out.println("Response body-----------------------------:\n" + responseBody);

            // Parsing JSON
            JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();

            // get object "enc_keys"
            JsonObject encKeys = jsonObject.getAsJsonObject("enc_keys");

            if (encKeys != null) {
                String emvksn = encKeys.get("emv_ksn").getAsString();
                String emvipek = encKeys.get("emv_ipek").getAsString();
                String trackksn = encKeys.get("track_ksn").getAsString();
                String trackipek = encKeys.get("track_ipek").getAsString();
                String pinksn = encKeys.get("pin_ksn").getAsString();
                String pinipek = encKeys.get("pin_ipek").getAsString();

                //TODO: Use the private key to decrypt the data: emvKSN, emvIpek, pinIpek, pinKSN , trackKSN and trackIpek
                decryptedDataCDCPKey(emvksn, emvipek, pinksn, pinipek, trackksn, trackipek, privateKey);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void decryptedGeneralKeyWithPrivateKey(String amKsn, String amIpek, String gIpek, String gKsn, String privateKey) {
        try {
            amountKSN = decryptByPrivateKey(hexStringToBytes(amKsn), privateKey);
            amountIpek = decryptByPrivateKey(hexStringToBytes(amIpek), privateKey);
            generalIpek = decryptByPrivateKey(hexStringToBytes(gIpek), privateKey);
            generalKsn = decryptByPrivateKey(hexStringToBytes(gKsn), privateKey);

            System.out.println("-----------------------Process Decrypt Data using privateKey-------------------------");
            System.out.println("Amount KSN---------------: " + amountKSN); //TODO: From the decrypted Amount KSN, take the last 20 characters
            System.out.println("Amount IPEK--------------: " + amountIpek); //TODO: From the decrypted Amount IPEK, take the last 32 characters
            System.out.println("General IPEK-------------: " + generalIpek); //TODO: From the decrypted General IPEK, take the last 32 characters
            System.out.println("General KSN--------------: " + generalKsn); //TODO: From the decrypted General KSN, take the last 20 characters

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }
    }

    private static void decryptedDataCDCPKey(String emvKsn, String emvIpek, String pinKsn, String pinIpek, String trackKsn, String trackIpek, String privateKey) {
        try {
            emvKSN = decryptByPrivateKey(hexStringToBytes(emvKsn), privateKey);
            emvIPEK = decryptByPrivateKey(hexStringToBytes(emvIpek), privateKey);
            pinKSN = decryptByPrivateKey(hexStringToBytes(pinKsn), privateKey);
            pinIPEK = decryptByPrivateKey(hexStringToBytes(pinIpek), privateKey);
            trackKSN = decryptByPrivateKey(hexStringToBytes(trackKsn), privateKey);
            trackIPEK = decryptByPrivateKey(hexStringToBytes(trackIpek), privateKey);

            System.out.println("-----------------------Process Decrypt Data using privateKey-------------------------");
            System.out.println("Emv KSN---------------: " + emvKSN); //TODO: From the decrypted Emv KSN, take the last 20 characters
            System.out.println("Emv IPEK--------------: " + emvIPEK); //TODO: From the decrypted Emv IPEK, take the last 32 characters
            System.out.println("Pin IPEK-------------: " + pinKSN); //TODO: From the decrypted Pin IPEK, take the last 32 characters
            System.out.println("Pin KSN--------------: " + pinIPEK); //TODO: From the decrypted Pin KSN, take the last 20 characters
            System.out.println("Track KSN--------------: " + trackKSN); //TODO: From the decrypted Track KSN, take the last 20 characters
            System.out.println("Track Ipek--------------: " + trackIPEK); //TODO: From the decrypted Track Ipek, take the last 32 characters


        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }
    }

    private static String generateEncAmount(long amountData) {
        //TODO: 1. Create KSN Index
        sAmountKsnIndex = generateRandomHexString();

        //TODO: 2. For Amount KSN, take the first 15 characters and append the KSN Index
        String amountKsn = amountKSN.substring(0, 15) + sAmountKsnIndex;
        byte[] baAmountKsn = hexStringToBytes(amountKsn);
        sAmountKsn = bytesToHex(baAmountKsn);

        //TODO: 3. Handle Amount IPEK
        byte[] baAmountIpek = hexStringToBytes(amountIpek);

        //TODO: 4. Convert plain amount (Long) to HexString
        String hsBaseAmount = Long.toHexString(amountData);
        if (hsBaseAmount.length() % 2 != 0) {
            hsBaseAmount = "0" + hsBaseAmount;
        }
        int iModulus = (hsBaseAmount.length() / 2) % 8;
        if (iModulus != 0) {
            StringBuilder sb = new StringBuilder(hsBaseAmount);
            for (int i = 0; i < 8 - iModulus; i++) {
                sb.insert(0, "00");
            }
            hsBaseAmount = sb.toString();
        }
        hsBaseAmount = hsBaseAmount.toUpperCase();
        byte[] baBaseAmount = hexStringToBytes(hsBaseAmount);

        //TODO: 5. Process Amount Encryption
        byte[] baEncBaseAmount = DUKPTUtil.encryptAmountWithIPEK(baBaseAmount, baAmountKsn, baAmountIpek);
        sAmountEnc = bytesToHex(baEncBaseAmount).toUpperCase();

        //TODO: 6. Generate SHA-512 hash from the amount
        try {
            sAmountSHA512 = generateSHA512(hsBaseAmount);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        System.out.println("-------------------------------Process Encrypted Amount----------------------------------");
        System.out.println("AMOUNT KSN INDEX--------------------: " + sAmountKsnIndex);
        System.out.println("AMOUNT KSN--------------------------: " + sAmountKsn);
        System.out.println("AMOUNT IPEK-------------------------: " + bytesToHex(baAmountIpek));
        System.out.println("AMOUNT Data Plain-------------------: " + amountData);
        System.out.println("AMOUNT Data Hex---------------------: " + bytesToHex(baBaseAmount));
        System.out.println("AMOUNT Result Encrypted-------------: " + sAmountEnc);
        System.out.println("AMOUNT Result SHA512----------------: " + sAmountSHA512);
        return sAmountEnc;
    }

    private static String encTrack2Data(String track2Data) {
        //TODO: 1. Create KSN Index
        sTrack2KsnIndex = generateRandomHexString();

        //TODO: 2. For Track KSN, take the first 15 characters and append the KSN Index
        String strack2Ksn = trackKSN.substring(0, 15) + sTrack2KsnIndex;
        byte[] baTrack2Ksn = hexStringToBytes(strack2Ksn);
        sTrack2Ksn = bytesToHex(baTrack2Ksn);

        //TODO: 3. Handle Track2Data IPEK
        byte[] baTrackIpek = hexStringToBytes(trackIPEK);

        String hsBaseTrack2Data = track2Data;
        sTrackLength = hsBaseTrack2Data.length();

        if (sTrackLength % 2 == 1) {
            hsBaseTrack2Data += "0";
            sTrackLength += 1;
        }

        int iModulus = (sTrackLength / 2) % 8;
        if (iModulus != 0) {
            for (int i = 0; i < 8 - iModulus; i++) {
                hsBaseTrack2Data += "00";
            }
        }
        hsBaseTrack2Data = hsBaseTrack2Data.toUpperCase();
        byte[] baBaseTrack2 = hexStringToBytes(hsBaseTrack2Data);

        //TODO: 4. Process Track2Data Encryption
        byte[] baEncBaseTrack2 = DUKPTUtil.encryptTrackWithIPEK(baBaseTrack2, baTrack2Ksn, baTrackIpek);
        sTrackEnc = bytesToHex(baEncBaseTrack2).toUpperCase();


        //TODO: 5. Generate SHA-512 hash from the track2Data
        try {
            sTrackSHA512 = generateSHA512(track2Data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        System.out.println("-------------------------------TRACK 2 Data----------------------------------");
        System.out.println("Track2Data KSN INDEX--------------------: " + sTrack2KsnIndex);
        System.out.println("Track2Data KSN--------------------------: " + sTrack2Ksn);
        System.out.println("Track2Data IPEK-------------------------: " + bytesToHex(baTrackIpek));
        System.out.println("Track2Data Data Plain-------------------: " + track2Data);
        System.out.println("Track2Data Result Sha512----------------: " + sTrackSHA512);
        System.out.println("Track2Data Result Encrypted-------------: " + sTrackEnc);
        return sTrackEnc;
    }

    private static String encEmvData(String emvData) {

        //TODO: 1. Create KSN Index
        sEmvKsnIndex = generateRandomHexString();

        //TODO: 2. For Emv KSN, take the first 15 characters and append the KSN Index
        String semvKsn = emvKSN.substring(0, 15) + sEmvKsnIndex;
        byte[] baEmvKsn = hexStringToBytes(semvKsn);
        sEmvKsn = bytesToHex(baEmvKsn);

        //TODO: 3. Handle Emv IPEK
        byte[] baEmvIpek = hexStringToBytes(emvIPEK);

        String hsBaseEmvData = emvData;
        sEmvLength = hsBaseEmvData.length();
        int padding = (8 - ((sEmvLength / 2) % 8)) % 8;
        for (int i = 0; i < padding; i++) {
            hsBaseEmvData += "00";
        }
        hsBaseEmvData = hsBaseEmvData.toUpperCase();
        byte[] baBaseEmvData = hexStringToBytes(hsBaseEmvData);

        //TODO: 4. Process Emv Encryption
        byte[] baEncBaseEmvData = DUKPTUtil.encryptTrackWithIPEK(baBaseEmvData, baEmvKsn, baEmvIpek);
        sEmvEnc = bytesToHex(baEncBaseEmvData).toUpperCase();

        System.out.println("-------------------------------EMV Data----------------------------------");
        System.out.println("EMV KSN INDEX--------------------: " + sEmvKsnIndex);
        System.out.println("EMV KSN--------------------------: " + sEmvKsn);
        System.out.println("EMV IPEK-------------------------: " + bytesToHex(baEmvIpek));
        System.out.println("EMV Data Plain-------------------: " + emvData);
        System.out.println("EMV Data Plain Length------------: " + sEmvLength);
        System.out.println("EMV Result Encrypted-------------: " + sEmvEnc);
        return sEmvKsn;
    }

    private static String encPinData(String pinBlockData) {
        //TODO: 1. Create KSN Index
        sPinKsnIndex = generateRandomHexString();

        //TODO: 2. For Emv KSN, take the first 15 characters and append the KSN Index
        String spinKsn = pinKSN.substring(0, 15) + sPinKsnIndex;
        byte[] baPinKsn = hexStringToBytes(spinKsn);
        sPinKsn = bytesToHex(baPinKsn);

        //TODO: 3. Handle PinBlock IPEK
        byte[] baPinIpek = hexStringToBytes(pinIPEK);

        String hsBasePinBlockData = pinBlockData;
        sPinLength = hsBasePinBlockData.length();

        byte[] baPinBlockData = hexStringToBytes(hsBasePinBlockData);

        //TODO: 4. Process PINBlock Encryption
        byte[] baEncPinBlock = DUKPTUtil.encryptPINBlockWithIPEK(baPinBlockData, baPinKsn, baPinIpek);
        sPinEnc = bytesToHex(baEncPinBlock).toUpperCase();

        System.out.println("-------------------------------PinBlock Data----------------------------------");
        System.out.println("PinBlock KSN INDEX--------------------: " + sPinKsnIndex);
        System.out.println("PinBlock KSN--------------------------: " + sPinKsn);
        System.out.println("PinBlock IPEK-------------------------: " + bytesToHex(baPinIpek));
        System.out.println("PinBlock Data Plain Length-------------------: " + sPinLength);
        System.out.println("PinBlock Data Plain-------------------: " + pinBlockData);
        System.out.println("PinBlock Result Encrypted-------------: " + sPinEnc);
        return sPinEnc;
    }

    private static void doSaleTrx() {
        try {
            String endPoint = URL + "MmCoreCdcpHost/v1/sale/sale_trx";

            String pos_cloud_pointer = String.format("DRC-%s-%s", "CSZ", generateRandomID()); //TODO format DRC-initialMerchant-UUID Random
            OkHttpClient client = new OkHttpClient();
            long timestamp = getCurrentTimestamp();

            //JSON body generate QRCode
            Map<String, Object> jsonBody = new HashMap<>();
            jsonBody.put("amount_ksn_index", sAmountKsnIndex);
            jsonBody.put("base_amount_enc", sAmountEnc);
            jsonBody.put("base_amount_hash", sAmountSHA512);
            jsonBody.put("device_id", "PB10211W21557"); //TODO: Replace with the serial number (SN) of the device you are using.
            jsonBody.put("trx_mode", 1);
            jsonBody.put("device_timestamp", String.valueOf(timestamp));
            jsonBody.put("entry_mode", "051"); //TODO 051 for dip 072 for tap
            jsonBody.put("is_refund", false);
            jsonBody.put("emv_req_len", sEmvLength);
            jsonBody.put("emv_ksn_index", sEmvKsnIndex); //Emv KSN Index
            jsonBody.put("emv_req_enc", sEmvEnc);
            jsonBody.put("pin_ksn_index", sPinKsnIndex); //PIN KSN Index
            jsonBody.put("pinblock_enc", sPinEnc);
            jsonBody.put("pos_cloud_pointer", pos_cloud_pointer);
            jsonBody.put("pos_request_type", "1");
            jsonBody.put("track_2_hash", sTrackSHA512);
            jsonBody.put("track_2_enc", sTrackEnc);
            jsonBody.put("track_2_len", sTrackLength);
            jsonBody.put("track_ksn_index", sTrack2KsnIndex); //Track2 KSN Index


            String json = new Gson().toJson(jsonBody);

            RequestBody requestBody = RequestBody.create(
                    json,
                    MediaType.parse("application/json")
            );

            Request request = new Request.Builder()
                    .url(endPoint)
                    .post(requestBody)
                    .addHeader("Content-Type", "application/json")
                    .addHeader("Authorization", token)
                    .addHeader("hit-from", "rest-1751866232-AWSA1FAV") //TODO format {Prefix}-{device_timestamp}-{random 8 alphanumeric}
                    .build();

            System.out.println("-------------------------Process sale------------------------------------");
            System.out.println("URL path sale_trx-------:" + request.url().url().getPath());
            System.out.println("Request body------------------:\n" + json);
            try (Response response = client.newCall(request).execute()) {
                String responseBody = response.body().string();
                System.out.println("Response body-----------------:\n" + responseBody);

                //TODO EXAMPLE RESPONSE SUCCESS
                //TODO {
                //  "response_code": "0020",
                //  "is_debit_flag": true,
                //  "card_expiry_date": "2908",
                //  "card_holder_name": "",
                //  "batch_group": "BNI_DEBIT",
                //  "mid": "000100914031166",
                //  "tid": "91416602",
                //  "host_date": "0707",
                //  "pos_request_type": "1",
                //  "invoice_num": "010900",
                //  "base_amount": 555,
                //  "approval_code": "125221",
                //  "midware_timestamp": "1751867541",
                //  "message": "SALE APPROVED.",
                //  "batch_num": "000018",
                //  "version": {
                //    "crypto_ver": "v1.5.0",
                //    "cdcp_ver": "v1.0.3"
                //  },
                //  "emv_ksn_index": "84D8C",
                //  "rrn": "000000011296",
                //  "emv_res_enc": "D043ACCCC84CD48AEE0EB09991B12E4A",
                //  "container_env_name": "cash-prod.octopus.be1.docker",
                //  "masked_pan": "537941******7809",
                //  "print_receipt_merchant_name": "Cashlez IT 2",
                //  "bin_result": "BCA_DEBIT_BIN2",
                //  "host_time": "125221",
                //  "print_receipt_address_line_2": "Jakarta Pusat,Tanah Abang",
                //  "print_receipt_address_line_1": "Gd Atria @Sudirman Lt.23",
                //  "emv_res_len": 24,
                //  "status": "OK"
                //TODO }
            } catch (IOException e) {
                e.printStackTrace();
                System.out.println("Response body IOException-----------------:\n" + e);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //TODO: Function to generate KSN index (random hex string)
    private static String generateRandomHexString() {
        String hexRandom;
        Random random = new Random();
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            hexString.append(Integer.toHexString(random.nextInt(16)).toUpperCase());
        }

        hexRandom = hexString.toString();
        return hexRandom;
    }

    private static String generateRandomID() {
        String hexRandom;
        Random random = new Random();
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i <= 15; i++) {
            hexString.append(Integer.toHexString(random.nextInt(16)).toUpperCase());
        }

        hexRandom = hexString.toString();
        return hexRandom;
    }

    public static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || hexString.isEmpty()) {
            return null;
        }

        byte[] buffer = new byte[hexString.length() >> 1];
        int stringLength = hexString.length();
        int byteIndex = 0;

        for (int i = 0; i < stringLength; i++) {
            char ch = hexString.charAt(i);
            if (ch == ' ') {
                continue;
            }

            byte hex = isHexChar(ch);
            if (hex < 0) {
                return null;
            }

            int shift = (byteIndex % 2 == 1) ? 0 : 4;
            buffer[byteIndex >> 1] = (byte) (buffer[byteIndex >> 1] | (hex << shift));
            byteIndex++;
        }

        byteIndex >>= 1; // Divide by 2
        if (byteIndex > 0) {
            if (byteIndex < buffer.length) {
                byte[] newBuffer = new byte[byteIndex];
                System.arraycopy(buffer, 0, newBuffer, 0, byteIndex);
                return newBuffer;
            }
        } else {
            return null;
        }
        return buffer;
    }

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static byte isHexChar(char ch) {
        if (ch >= '0' && ch <= '9') {
            return (byte) (ch - '0');
        }
        if (ch >= 'A' && ch <= 'F') {
            return (byte) (ch - 'A' + 10);
        }
        if (ch >= 'a' && ch <= 'f') {
            return (byte) (ch - 'a' + 10);
        }
        return -1; // Invalid hex character
    }

    //TODO: Function to generate SHA-512
    private static String generateSHA512(String data) throws NoSuchAlgorithmException {
        MessageDigest mdSHA512 = MessageDigest.getInstance("SHA-512");
        byte[] baSHA512 = mdSHA512.digest(data.getBytes(StandardCharsets.UTF_8));
        return byteArrayToHexString(baSHA512).toLowerCase();
    }

    private static String byteArrayToHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;

        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX[v >>> 4];
            hexChars[j * 2 + 1] = HEX[v & 0x0F];
        }

        return new String(hexChars);
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String toHexString(byte[] byteArray) {
        return toHexString(byteArray, 0, byteArray.length, false);
    }

    public static String toHexString(byte[] byteArray, int beginIndex, int endIndex, boolean spaceFlag) {
        if (byteArray == null || byteArray.length == 0 || beginIndex < 0 || endIndex > byteArray.length || beginIndex >= endIndex) {
            return "";
        }

        StringBuilder sbuf = new StringBuilder();

        sbuf.append(toHexChar((byteArray[beginIndex] >> 4) & 0xF));
        sbuf.append(toHexChar(byteArray[beginIndex] & 0xF));

        for (int i = beginIndex + 1; i < endIndex; i++) {
            if (spaceFlag) sbuf.append(" ");
            sbuf.append(toHexChar((byteArray[i] >> 4) & 0xF));
            sbuf.append(toHexChar(byteArray[i] & 0xF));
        }
        return sbuf.toString();
    }

    private static char toHexChar(int nibble) {
        return "0123456789ABCDEF".charAt(nibble & 0xF);
    }

    public static byte[] desEncrypt(byte[] input, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (key.length != 8) {
            throw new InvalidKeyException("@ DESCryptoUtil.desEncrypt(). Parameter <key> must be 8 bytes long, but was " + key.length + ".");
        }

        if (input.length != 8) {
            throw new IllegalBlockSizeException("@ DESCryptoUtil.desEncrypt(). Parameter <input> must be 8 bytes long, but was " + input.length + ".");
        }

        Cipher desCipher = Cipher.getInstance("DES/ECB/NoPadding");
        SecretKey keySpec = new SecretKeySpec(key, "DES");
        desCipher.init(Cipher.ENCRYPT_MODE, keySpec);

        return desCipher.doFinal(input);
    }

    public static String hexStringToAsciiString(String hex) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            int decimal = Integer.parseInt(str, 16);
            output.append((char) decimal);
        }
        return output.toString();
    }

    //TODO: Function to encrypt using MD5
    public static String encryptByMD5(String txt) {
        StringBuffer stringBuffer = new StringBuffer();
        String strKu = null;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(txt.getBytes());
            byte[] byteString = messageDigest.digest();
            strKu = bytesToHex(byteString);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strKu.toLowerCase();
    }

    //TODO: Function to generate timestamp
    public static long getCurrentTimestamp() {
        return System.currentTimeMillis();
    }

    public static String encryptBySHA256(String txt) {
        StringBuilder stringBuffer = new StringBuilder();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(txt.getBytes());
            byte[] byteString = messageDigest.digest();
            for (byte tmpStrByte : byteString) {
                String tmpEncTxt = Integer.toString((tmpStrByte & 0xff) + 0x100, 16).substring(1);
                stringBuffer.append(tmpEncTxt);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return stringBuffer.toString();
    }

    public static String hexToString(String hex) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

}