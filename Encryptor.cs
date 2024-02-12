/**
 * Author: Jonathon LoTempio
 */

using System.Collections;
using System.ComponentModel.DataAnnotations;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Newtonsoft.Json;
using System.Text.Json.Serialization;
using Messenger;

/// <summary>
/// PublicKey class is used to serialize and deserialize the public key json
/// contains an email and key string
/// </summary>
public class PublicKey
{
    public String email;
    public String key;


    public PublicKey(String email, String key )
    {
        this.email = email;
        this.key = key;
    }
}


/// <summary>
/// PrivateKey class is used to serialize and deserialize the private key json
/// contains a list of emails and key string
/// </summary>
public class PrivateKey
{
    public List<String> email;
    public String key;


    public PrivateKey(List<String> email, String key )
    {
        this.email = email;
        this.key = key;
    }
}


/// <summary>
/// Message class is used to serialize and deserialize the message json
/// contains an email and cipher string
/// </summary>
public class Message
{
    public String email;
    public String content;
    
    public Message(String email, String content )
    {
        this.email = email;
        this.content = content;
    }
}





/// <summary>
/// Encryptor generates keys to communicate with a server, sending and receiving keys and messages.
/// </summary>
public class Encryptor
{
    /// <summary>
    ///     generate p and q to use in key generation
    /// </summary>
    /// <param name="size"> size of key to generate, usually 1024</param>
    /// <returns>returns a BigInteger array [p,q]</returns>
    public BigInteger[] get_pq(int size)
    {
        var primeFinder = new PrimeFinder();
        float variance = RandomNumberGenerator.GetInt32(20, 30) * (RandomNumberGenerator.GetInt32(-1, 1) * 2 + 1);
        int approxPSize = (int)(size / (2.0 * (1 + .01 * variance)));
        int pSize = approxPSize - approxPSize % 8;
        int qSize = size - pSize;
        BigInteger[] result = { primeFinder.GetPrime(pSize), primeFinder.GetPrime(qSize) };
        return result;
    }


    /// <summary>
    ///     generate E,N, and D to use in creating public and private keys
    /// </summary>
    /// <param name="size">size of p and q combined</param>
    /// <returns>returns a BigInteger array [E,N,D]</returns>
    public BigInteger[] get_keys(int size)
    {
        var primeFinder = new PrimeFinder();
        var pq = get_pq(size);
        var p = pq[0];
        var q = pq[1];
        var N = p * q;
        var r = (p - 1) * (q - 1);
        var E = primeFinder.GetPrime(16);
        var D = ModInverse(E, r);
        return new[] { E, N, D };

    }


    /// <summary>
    ///     performs the modInverse operation on a and n
    /// </summary>
    /// <param name="a"> BigInteger to modInverse</param>
    /// <param name="n">BigInteger to modInverse by</param>
    /// <returns>ModInverse of a and n</returns>
    static BigInteger ModInverse(BigInteger a, BigInteger n)
    {
        BigInteger i = n, v = 0, d = 1;
        while (a > 0)
        {
            BigInteger t = i / a, x = a;
            a = i % x;
            i = x;
            x = d;
            d = v - t * x;
            v = x;
        }

        v %= n;
        if (v < 0) v = (v + n) % n;
        return v;
    }


    /// <summary>
    ///     Base64 encodes public or private key values
    /// </summary>
    /// <param name="EorD"> E if public key, D if private key</param>
    /// <param name="N"> N used in key generation</param>
    /// <returns>returns a Base64Encoded string that represents a public or private key.</returns>
    public static string EncodeKey(BigInteger EorD, BigInteger N)
    {
        byte[] encodedEorD = EncodeBigInt(EorD);
        byte[] encodedN = EncodeBigInt(N);
        byte[] finalKey = new byte[encodedEorD.Length + encodedN.Length];
        Buffer.BlockCopy(encodedEorD, 0, finalKey, 0, encodedEorD.Length);
        Buffer.BlockCopy(encodedN, 0, finalKey, encodedEorD.Length, encodedN.Length);
        string encodedKey = Convert.ToBase64String(finalKey);
        return encodedKey;
    }


    /// <summary>
    ///     convert a bigInteger into byte array, the first 4 bytes store the size big endian,
    ///     and the rest is the actual BigInteger little endian.
    /// </summary>
    /// <param name="bigInt">BigInteger to be encoded</param>
    /// <returns>returns a byte array of bigIntKey</returns>
    public static byte[] EncodeBigInt(BigInteger bigInt)
    {
        byte[] bigIntKey = new byte[4 + bigInt.GetByteCount()];
        byte[] bigIntSize = BitConverter.GetBytes(bigInt.GetByteCount());
        byte[] reversedSize = bigIntSize.Reverse().ToArray();
        Buffer.BlockCopy(reversedSize, 0, bigIntKey, 0, 4);
        Buffer.BlockCopy(bigInt.ToByteArray(), 0, bigIntKey, 4, bigInt.GetByteCount());

        return bigIntKey;
    }


    /// <summary>
    ///     generates and files a public key into public.key,
    ///     and files a private key into private.key
    /// </summary>
    public void GenerateKeys(int size)
    {
        var end = get_keys(size);
        string publicKey = EncodeKey(end[0], end[1]);
        string privateKey = EncodeKey(end[2], end[1]);
        var prvkey = new PrivateKey(new List<string>(), privateKey);
        var pubkey = new PublicKey("", publicKey);
        File.WriteAllText("public.key", JsonConvert.SerializeObject(pubkey));
        File.WriteAllText("private.key", JsonConvert.SerializeObject(prvkey));
    }


    /// <summary>
    ///     converts a byte array into a BigInteger array [EorD,N]
    ///     EorD: E if public key, D if private key
    /// </summary>
    /// <param name="bytes">byte array from base64encoded key string</param>
    /// <returns>return a BigInteger array [EorD,N]</returns>
    public static BigInteger[] ReadKey(byte[] bytes)
    {
        int offset = 0;
        int count = 4;
        var resultArray = new BigInteger[2];
        for (int i = 0; i < resultArray.Length; i++)
        {
            byte[] keySize = bytes[offset..(offset + count)];
            offset += count;
            keySize = keySize.Reverse().ToArray();
            int size = BitConverter.ToInt32(keySize);
            byte[] temp = bytes[offset..(offset + size)];
            offset += size;
            resultArray[i] = new BigInteger(temp);
        }

        return resultArray;
    }


    /// <summary>
    ///     connects to http://kayrun.cs.rit.edu:5000 to get the public key
    ///     for a certain user, then files the public key in "[email].key" format
    /// </summary>
    /// <param name="email">email to get public key from</param>
    public void GetKey(string email)
    {
        var client = new HttpClient();
        var result = client.GetStringAsync("http://kayrun.cs.rit.edu:5000/Key/" + email);
        string emailKey = result.Result;
        string filename = email + ".key";
        File.WriteAllText(filename, emailKey);
    }


    /// <summary>
    ///     sends public key from public.key to http://kayrun.cs.rit.edu:5000/Key/email
    /// </summary>
    /// <param name="email"> email to send the key to</param>
    public void SendKey(string email)
    {
        var client = new HttpClient();
        string uri = "http://kayrun.cs.rit.edu:5000/Key/" + email;
        var publicKey = JsonConvert.DeserializeObject<PublicKey>(ReadKeyFile("public.key")) ?? throw new InvalidOperationException() ;
        publicKey.email = email;
        string json = JsonConvert.SerializeObject(publicKey);
        HttpContent content = new StringContent(json, Encoding.UTF8, "application/json");
        var result = client.PutAsync(uri, content);
        if (result.Result.IsSuccessStatusCode)
        {
            var privateKey = JsonConvert.DeserializeObject<PrivateKey>(ReadKeyFile("private.key")) ?? throw new InvalidOperationException();
            privateKey.email.Add(email);
            File.WriteAllText("private.key", JsonConvert.SerializeObject(privateKey));
            Console.WriteLine("Key saved");
        }
        else
        {
            Console.WriteLine("Error sending key, result code: {0}", result.Result.StatusCode);
        }
    }


    /// <summary>
    ///     attempts to read a file. If the file does not exists, writes
    ///     a console error and exits the program.
    /// </summary>
    /// <param name="filename">file to read</param>
    /// <returns>string representing a public or private key json object</returns>
    public static string ReadKeyFile(string filename)
    {
        try
        {
            using (var r = new StreamReader(filename))
            {
                string json = r.ReadToEnd();
                return json;
            }
        }
        catch (FileNotFoundException)
        {
            Console.WriteLine("Key does not exist for {0}", filename);
            Environment.Exit(0);
            return "";
        }

    }


    /// <summary>
    ///     encrypts a message using E and N, then base64 encodes the message
    /// </summary>
    /// <param name="message">message string to encrypt and encode</param>
    /// <param name="E">E part of public key</param>
    /// <param name="N">N part of public key</param>
    /// <returns>base64 encoded,encrypted,message</returns>
    public static string EncryptMessage(string message, BigInteger E, BigInteger N)
    {
        byte[] mAsBytes = Encoding.UTF8.GetBytes(message);
        var bigIntM = new BigInteger(mAsBytes);
        byte[] result = BigInteger.ModPow(bigIntM, E, N).ToByteArray();
        string cipher = Convert.ToBase64String(result);
        return cipher;
    }


    /// <summary>
    ///     decrypts a message using D and N
    /// </summary>
    /// <param name="cipher">base64 encoded cipher to decode and decrypt</param>
    /// <param name="D">D part of private key</param>
    /// <param name="N">N part of private key</param>
    /// <returns>plaintext message</returns>
    public static string DecryptMessage(string cipher, BigInteger D, BigInteger N)
    {
        byte[] cipherBytes = Convert.FromBase64String(cipher);
        var bigIntC = new BigInteger(cipherBytes);
        byte[] result = BigInteger.ModPow(bigIntC, D, N).ToByteArray();
        string message = Encoding.UTF8.GetString(result);
        return message;
    }


    /// <summary>
    ///     attempts to send a message to specified user.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="email"></param>
    public void SendMsg(string message, string email)
    {
        string filename = email + ".key";
        string jsonKey = ReadKeyFile(filename);
        var publicKey = JsonConvert.DeserializeObject<PublicKey>(ReadKeyFile(filename)) ?? throw new InvalidOperationException();
        string key = publicKey.key;
        byte[] keyBytes = Convert.FromBase64String(key);
        var results = ReadKey(keyBytes);
        string cipher = EncryptMessage(message, results[0], results[1]);

        var client = new HttpClient();
        string uri = "http://kayrun.cs.rit.edu:5000/Message/" + email;
        var json = new JsonObject();
        json["email"] = email;
        json["content"] = cipher;
        HttpContent content = new StringContent(json.ToJsonString(), Encoding.UTF8, "application/json");
        var result = client.PutAsync(uri, content);
        if (result.Result.IsSuccessStatusCode)
            Console.WriteLine("Message Written");
        else
            Console.Error.WriteLine("Error sending message, response code: {0}", result.Result.StatusCode);
    }


    /// <summary>
    ///     gets message json from http://kayrun.cs.rit.edu:5000/Message/email
    ///     decrypts message if the private key can decrypt the message. Otherwise
    ///     prints an error.
    /// </summary>
    /// <param name="email"> email used to get the message </param>
    public void GetMsg(string email)
    {
        var client = new HttpClient();
        string uri = "http://kayrun.cs.rit.edu:5000/Message/" + email;
        var request = client.GetStringAsync(uri);
        string result = request.Result;
        var jsonMessage = JsonConvert.DeserializeObject<Message>(result) ?? throw new InvalidOperationException();
        string messageEmail = jsonMessage.email;
        string cipher = jsonMessage.content;
        string jsonKey = ReadKeyFile("private.key");
        PrivateKey privateKey = JsonConvert.DeserializeObject<PrivateKey>(jsonKey) ??
                                throw new InvalidOperationException();
        List<String> keyEmails = privateKey.email;
        bool canDecrypt = false;
        foreach (var keyEmail in keyEmails)
        {
            if (keyEmail != null)
            {
                if (keyEmail.ToString().Equals(messageEmail))
                {
                    canDecrypt = true;
                    break;
                }
            }
        }

        if (!canDecrypt)
        {
            Console.WriteLine("cannot decrypt message, private key does not match public key used.");
            Environment.Exit(0);
        }

        string key = privateKey.key;
        byte[] keyBytes = Convert.FromBase64String(key);
        var results = ReadKey(keyBytes);
        if (cipher != null)
        {
            string message = DecryptMessage(cipher, results[0], results[1]);
            Console.WriteLine(message);
        }
    }

    public static void Main(string[] args)
    {
        try
        {
            var encryptor = new Encryptor();
            var validCommands = "commands are:\nkeyGen [keySize]\nsendKey [email]\ngetKey [email]\n" +
                                "sendMsg [email] [message]\ngetMsg [email]";
            if (args.Length < 1)
            {
                Console.Error.WriteLine("Please enter a command\n{0}", validCommands);
                Environment.Exit(0);
            }

            if (args[0] == "keyGen")
            {
                if (args.Length != 2) throw new ArgumentException();
                int size = Convert.ToInt32(args[1]);
                encryptor.GenerateKeys(size);
            }
            else if (args[0] == "sendKey")
            {
                if (args.Length != 2) throw new ArgumentException();
                encryptor.SendKey(args[1]);
            }
            else if (args[0] == "getKey")
            {
                if (args.Length != 2) throw new ArgumentException();
                encryptor.GetKey(args[1]);
            }
            else if (args[0] == "sendMsg")
            {
                if (args.Length != 3) throw new ArgumentException();
                encryptor.SendMsg(args[2], args[1]);
            }
            else if (args[0] == "getMsg")
            {
                if (args.Length != 2) throw new ArgumentException();
                encryptor.GetMsg(args[1]);
            }
            else
            {
                Console.Error.WriteLine("'{0}' is not a valid command\n{validCommands}", args[0],validCommands);
            }
        }
        catch (InvalidOperationException)
        {
            Console.Error.WriteLine("Error: could not serialize json");
            Environment.Exit(0);
        }
        catch (ArgumentException)
        {
            Console.Error.WriteLine("invalid amount of arguments,\n" +
                                    "commands arguments are:\nkeyGen [keySize]\nsendKey [email]\ngetKey [email]\n"+
                                    "sendMsg [email] [message]\ngetMsg [email]");
            Environment.Exit(0);
        }
        catch (FormatException)
        {
            Console.Error.WriteLine("Invalid input. Please enter a valid integer");
            Environment.Exit(0);
        }
    }
}
