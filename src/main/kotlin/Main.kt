import java.math.BigInteger
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

fun main() {
//    println("Encrypted String: ${encryptString("Now it is okey!")}")
    print("Please enter Encryption/Decryption key: ")
    val encryptionKey= if(readln().isEmpty()){
        "tstymzmjklgiubvx%8\$#9*&*5):?><:p"
    }else{
        readln()
    }
    print("Press 1 for Encryption and Press 2 for Decryption: ")
    val selection = readln().toInt()
    if (selection == 1) {
        print("Enter Encrypted String: ")
        val decString = readln()
        println("Encrypted String: ${encryptString(decString,encryptionKey)}")
        println("SHA512: ${getSHA512(encryptString(decString, encryptionKey)!!,encryptionKey)}")
    } else if (selection == 2) {
        print("Enter Decrypted String: ")
        val decString = readln()
        println("Decrypted String: ${decryptString(decString,encryptionKey)}")
        println("SHA512: ${getSHA512(decString,encryptionKey)}")
    }
}
fun decryptString(encryptedString: String, encryptionKey: String): String {
    // Parameters
    val algorithmNonceSize = 12
    val algorithmKeySize = 32
    val PBKDF2SaltSize = 16
    val PBKDF2Iterations = 26834
    val encryptedString = encryptedString

    // Decode the encrypted string from base64
    val encryptedData = Base64.getDecoder().decode(encryptedString)

    // Derive the key using PBKDF2
    val salt = encryptedData.copyOfRange(0, PBKDF2SaltSize)
    val keySpec = PBEKeySpec(encryptionKey.toCharArray(), salt, PBKDF2Iterations, algorithmKeySize * 8)
    val secretKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(keySpec)
    val derivedKey = secretKey.encoded

    // Extract the nonce and ciphertext
    val nonce = encryptedData.copyOfRange(PBKDF2SaltSize, PBKDF2SaltSize + algorithmNonceSize)
    val ciphertext = encryptedData.copyOfRange(PBKDF2SaltSize + algorithmNonceSize, encryptedData.size)

    // Decrypt using AES 256 GCM
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpecAES = SecretKeySpec(derivedKey, "AES")
    val gcmParamSpec = GCMParameterSpec(128, nonce)
    cipher.init(Cipher.DECRYPT_MODE, keySpecAES, gcmParamSpec)
    val decryptedData = cipher.doFinal(ciphertext)

    // Convert decrypted bytes to string
    val decryptedString = String(decryptedData, StandardCharsets.UTF_8)
    return decryptedString

}

fun encryptString(text: String, encryptionKey: String): String? {
    // Parameters
    val algorithmNonceSize = 12
    val algorithmKeySize = 32
    val PBKDF2SaltSize = 16
    val PBKDF2Iterations = 26834
    val plaintext = text

    // Generate random nonce
    val nonce = ByteArray(algorithmNonceSize)
    SecureRandom().nextBytes(nonce)

    // Derive the key using PBKDF2
    val salt = ByteArray(PBKDF2SaltSize)
    SecureRandom().nextBytes(salt)

    val keySpec = PBEKeySpec(encryptionKey.toCharArray(), salt, PBKDF2Iterations, algorithmKeySize * 8)
    val secretKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(keySpec)
    val derivedKey = secretKey.encoded

    // Encrypt using AES 256 GCM
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpecAES = SecretKeySpec(derivedKey, "AES")
    val gcmParamSpec = GCMParameterSpec(128, nonce)
    cipher.init(Cipher.ENCRYPT_MODE, keySpecAES, gcmParamSpec)
    val ciphertext = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))

    // Concatenate salt + nonce + ciphertext for storage or transmission
    val encryptedData = ByteArray(PBKDF2SaltSize + algorithmNonceSize + ciphertext.size)
    System.arraycopy(salt, 0, encryptedData, 0, PBKDF2SaltSize)
    System.arraycopy(nonce, 0, encryptedData, PBKDF2SaltSize, algorithmNonceSize)
    System.arraycopy(ciphertext, 0, encryptedData, PBKDF2SaltSize + algorithmNonceSize, ciphertext.size)

    // Encode the encrypted data to base64 for readability or transmission
    val base64Encoded = Base64.getEncoder().encodeToString(encryptedData)

    return base64Encoded
}

fun getSHA512(input: String, encryptionKey: String):String{
    val md: MessageDigest = MessageDigest.getInstance("SHA-512")
    val messageDigest = md.digest(input.toByteArray())

    // Convert byte array into signum representation
    val no = BigInteger(1, messageDigest)

    // Convert message digest into hex value
    var hashtext: String = no.toString(16)

    // Add preceding 0s to make it 128 chars long
    while (hashtext.length < 128) {
        hashtext = "0$hashtext"
    }

    // return the HashText
    return hashtext
}
