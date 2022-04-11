//  Copyright 2022 Sébastian Dejonghe
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System.Security.Cryptography;
using System.Text;

void ExportEllipticCurvePrivateKey(ECDsa ecdsa, string pemPath)
{
    using var writer = new StreamWriter(pemPath);

    writer.Write(PemEncoding.Write("EC PRIVATE KEY", ecdsa.ExportECPrivateKey()));
}

void ExportEllipticCurvePublicKey(ECDsa ecdsa, string pemPath)
{
    using var writer = new StreamWriter(pemPath);

    writer.Write(PemEncoding.Write("PUBLIC KEY", ecdsa.ExportSubjectPublicKeyInfo()));
}

ECDsa ImportEllipticCurvePrivateKey(string pemPath)
{
    var ecdsa = ECDsa.Create();
    ecdsa.ImportFromPem(File.ReadAllText(pemPath));

    return ecdsa;
}

ECDsa ImportEllipticCurvePublicKey(string pemPath)
{
    var ecdsa = ECDsa.Create();
    ecdsa.ImportFromPem(File.ReadAllText(pemPath));

    return ecdsa;
}

string SignData(byte[] data)
{
    var ecdsa = ImportEllipticCurvePrivateKey("ecc.key");

    var signature = ecdsa.SignData(data, HashAlgorithmName.SHA384);

    return Convert.ToBase64String(data) + "." + Convert.ToBase64String(signature);
}

byte[] VerifyAndGetData(string signedData)
{
    int comma = signedData.IndexOf('.');

    if (comma < 0)
    {
        throw new ArgumentException("Invalid signed data");
    }

    var payload = Convert.FromBase64String(signedData.Substring(0, comma));

    var ecdsa = ImportEllipticCurvePublicKey("ecc.pub");

    var givenSignature = Convert.FromBase64String(signedData.Substring(comma + 1));

    if (!ecdsa.VerifyData(payload, givenSignature, HashAlgorithmName.SHA384))
    {
        throw new ArgumentException("Tampered data");
    }

    return payload;
}

{
    var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    ExportEllipticCurvePrivateKey(ecdsa, "ecc.key");
    ExportEllipticCurvePublicKey(ecdsa, "ecc.pub");
}

// Sign with the private key.

var plainText = Encoding.UTF8.GetBytes("Hello world!");

var signedData = SignData(plainText);

// Verify with the public key.

var verifiedData = VerifyAndGetData(signedData);

Console.WriteLine("Verified data: {0}", Encoding.UTF8.GetString(verifiedData));
