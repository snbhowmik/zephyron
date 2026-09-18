using System.Security.Cryptography;

class Hasher {
    static void Run() {
        var md5 = MD5.Create();
        var rsa = new RSACryptoServiceProvider(2048);
        var aes = Aes.Create();
    }
}
