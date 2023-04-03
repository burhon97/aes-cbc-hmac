import crypto from "node:crypto";

export class Aes256cbcHmac512 {
  keygen(): Promise<Uint8Array> {
    return new Promise<Uint8Array>(function (ok, fail) {
      crypto.generateKey(
        "aes",
        {
          length: 256,
        },
        (err, key) => {
          if (err) fail();
          ok(new Uint8Array(key.export()));
        }
      );
    });
  }

  aes256cbc_hmac512_encrypt(
    message: string | Uint8Array,
    key: Uint8Array
  ): {
    ciphertext: Uint8Array;
    key: Uint8Array;
    iv: Uint8Array;
    hmac: Uint8Array;
  } {
    const iv = new Uint8Array(Buffer.from(crypto.randomBytes(16)));

    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    const encryptedData = new Uint8Array(
      Buffer.concat([cipher.update(message), cipher.final()])
    );

    const hm = crypto.createHmac("sha512", key);
    hm.update(encryptedData);
    hm.update(key);
    hm.update(iv);
    const hmac = new Uint8Array(Buffer.from(hm.digest("hex")));

    return {
      ciphertext: encryptedData,
      iv: iv,
      hmac: hmac,
      key: key,
    };
  }

  aes256cbc_hmac512_decrypt({
    ciphertext,
    iv,
    hmac,
    key,
  }: {
    ciphertext: Uint8Array;
    iv: Uint8Array;
    hmac: Uint8Array;
    key: Uint8Array;
  }): Uint8Array {
    const hmacString = hmac.toString();

    const hm = crypto.createHmac("sha512", key);
    hm.update(ciphertext);
    hm.update(key);
    hm.update(iv);
    const newHmac = new Uint8Array(Buffer.from(hm.digest("hex")));
    const newHmacString = newHmac.toString();

    if (newHmacString != hmacString) {
      console.error("Bad HMAC control");
    }

    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    const decryptedData = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    return new Uint8Array(decryptedData);
  }
}
