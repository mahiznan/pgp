package com.span.open;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.sop.SOPImpl;
import sop.*;

import java.io.*;
import java.util.List;
import java.util.Scanner;

class PGPTest {

    private final String path = "/Users/rajeshkumarm/workspace/pgp/src/main/resources/keys/";

    @Test
    void testPGP() throws IOException {
        String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "lQdGBGarnigBEADTY6RHy6H1Q+5Rpt6M4bsHpwTv3tuB1q92h0G2zqRwdGOkDN/P\n" +
                "Bh7lc4QVZks04ZoUI1cRrjSTMkxC5gLGPwPFeWNX7LgMcpKmfhgX0c4fCQMDHJIM\n" +
                "1J1SQ2FXUGs6uexVunCIzhUI9mJfzijWtJOktv2p41rkzSJ2rj1Z+pd+fwQRhX2M\n" +
                "MxVqt8Vw0MlsStk8X9vx9A4zgubQV0viTZlb9EZkqSnHKNtMUtZHK38gsWmd3Ce9\n" +
                "xvfmL9/bsMB71HlH05OKSgdzjhRvRSb7/r9LwPDCJCuqdpZPqGDZQmHr8LqbZn8T\n" +
                "zU/bdPoN1NgyIA/mDpw5rbkzqycJihUMMgZlP1hV3V5IQip//1J3QIC4eMj0qyof\n" +
                "r0NS5fCTZBa4JlMRhliIuguaysbzp7s+SloQEf4m3E9hH/EFETLQLJO5ftPfYa4f\n" +
                "yIA4t+z2mo21O32ICGFFfdFLFU1FZFuOdKB8hWYQCEKUKxTvaly8i9eBEKd9xXeU\n" +
                "FnpfAFecUtJHgW0+IVVIybCJLxu+UuwP+/OlLEtMpjAiYLeVdyV90ixrYRzh72eR\n" +
                "3OB9eAXztmWzlip1o0BydQp87Z8bddZXmwzKnVOa2AkVCGHsnV9/D6cdJnviMNpy\n" +
                "04lyPG//t9Ud7ocVnUXYk91icXJEsjvKc/zM89oG7iCjzdh8LfXbv8uECQARAQAB\n" +
                "/gcDAkIfBW1D5j+N+mEcscHNlcW3X/Yn870w72IXFPDSOQhNMWVopHRb90lNIAsl\n" +
                "JA1Q2ZofWImiNgMYCgtPj2wIWnMTOiZxWV+CX2x0CCFNp8lWl3RPXP2nwa6bLDo1\n" +
                "G5vfnaCa2j5cHxhBT6lszb4xxAlH+ih9qciNAT2kAGVRUmRY73vG+MioRD1UZDZM\n" +
                "UYujrRUvPs1/z1W87jC+QD+218/DvLOgejd6pZCONSm7+LPqQbCEVe5QsyZelmsZ\n" +
                "qUNSURJAGPcmnuO2n1cyCbnxH8dPN+Nm7AqGvh9RPVbr1exTAMq8ipCt6ScUr5Ic\n" +
                "1ocAVAN/vLjKKUZ+tnFknhF/cw21Hx3ezQ6QJsqKVfeoHH9GFPOv0NRkK607LblY\n" +
                "h5m4W48j41hJc7rBvX+2gQfCDKzaEK2yNYzRY0xJdhS3ggCDuWCRn5IxOvSsQKy+\n" +
                "aRITtkRbvJ6EwsQ0QAd30sBZ9ORTUHYRS2nYHDQ8U5nf1kbRZJHTauxKVD2QVAox\n" +
                "c1UO+WOToyV0LErFbScJXHBrU9A+HPK1yZbteXskl1eYseQsqHZyjfshWyQ/+2Lk\n" +
                "KtO0AOthY1xU9uOWXzNn/saVNfy0zjSJqvTfgCqgXvOtweZNsm3d1PU+RvkSVedt\n" +
                "tV/WaVm5nUsgc74hPsMlosQakOfmmR2L9CC4tJMR92B34YtPQyNZgVfH1DHfJMtO\n" +
                "WCOZ/9uwVCNWaOVOlPnlOvl+rdJAzYFjJDnStaJrFR4RoWdtNJPI5d7gPolTAeH2\n" +
                "NKKj4RXDRjctCgK7jDFpkB5ffdfKUWDGPBak7YpIp3LTO6RF3gBZv+M3C7gl9Cgk\n" +
                "JNiv09EQkg20HRYHCcwOO/7yqxBj0BcD8iutPtDQDYuhESwWmJ8sv3XK/S9ZY5By\n" +
                "0zH8IuMSdmYWVxtORXIqzOmVp9Fs1PpB+5H7IZewgLbuTlHsjX1zfqaHg3/Oov2i\n" +
                "Y3qI9j8YbGMK6Yx+W4qa2UtNxkJ2XlcBsoX1iXapOSY3/OH/S1Er9E7XExQjjds0\n" +
                "NwyEV3V+IlpyVz46OOfASjQ87imIe7j9/GnPUvOPOxFz9kQv9GPmz/Wv5wZNSWP1\n" +
                "77o5l/iXkSCidpR6pPm4SW73Yo9ye5D4EyeCzePqUz3YqZ8Fp4aZVM1jY8888IGo\n" +
                "AIyMuelgGAy2MjNQGi6C/hKPWtxQL0i1cmR3kwfMMHYQpUUA8MV114zZGyCTyD1j\n" +
                "lRmMWKDNyQW+T/t0l2DN9zy/njIG5080P00cbz7iaZzWZNYF+mgzm4tq6CO4YMIV\n" +
                "vIGy7kZZxmQ5Zt29yu8hrJJd23Dc7hrl2XS5is/7/vPq+uyT0SNmPJ1To4jiCYBQ\n" +
                "wZ3SrnsZNERZgHHDeL/9ltj5B1NUjNfWOUJMqlOdmgPOLLKAk9UOlJj1JXEiRl9Z\n" +
                "wSfBFy6bVaUbPwQdjOA+gs5zbo9H7SLci9WQLn4bshbaY5O5jYTM6vHjuhxOExyd\n" +
                "ECn46z6F/zUFumjxj+HK46X0CF21w92D/kDhBkW2lE5cHLxA7SwdMZ/G+Ym7lJgX\n" +
                "9A8QuU9uFkUmykek3Al283u7r2O/v0aZOWm4PW0h8HT+CN3LtUb2P4Ga0Inn4EYh\n" +
                "2+Y3IYRn38XVHtZZ3jJo1vPb0iUJ3SC8u5iNuuDCrxD21QW9+4QDyJzLBzgD3grf\n" +
                "jF/7+PgDLJTTm8UCCGx6ygsYpwRMfJQ1E80lqcjGRMDxAuTd+khjPeUlxwMCqdpJ\n" +
                "GQ9LIy7KD4sbPZt/rMtz4P52JPh5X5QvRXa2o10XCnWTgKdP9CLLlde0PFJhamVz\n" +
                "aGt1bWFyIChUaGlzIGlzIHNhbXBsZSBQR1Aga2V5KSA8cmFqZXNoa3VtYXJAZ21h\n" +
                "aWwuY29tPokCVwQTAQgAQRYhBFX1mLYG9vlvY2PNIKzrv6d7ASKSBQJmq54oAhsD\n" +
                "BQkFo5qABQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEKzrv6d7ASKSjg8P\n" +
                "/1c/ECApsx6WW4me8zGn+CrhuE+KeEx58nFenkyT+4dxWdHpk+KnsGisSoo/lH38\n" +
                "POYTnOKOQt5Dj289RuN7WfvWMXVd2OQoqfkAB3tBtpQYxcyd0CuLqMMmR4SNGr1p\n" +
                "EU7dPe09UHvChlFCPIyLkEq96s9Vg+aFcXn0Qmz4RUoa/pt69dMoY7Tmdj0Ar9M6\n" +
                "mA0T9Ss4zs/WSU+/rGB0MrBSMNRm+jpx33O6LBP59WoGyOu+IFnkE7CYJXxn2iHr\n" +
                "XOT719YCeVsqqrPCmtavnIsz6SPW6mGq9ReUy3ETydvfxi4wJW1z6MKvQ5nfIgYz\n" +
                "POkwvsLHqnr9vGTVBflQ7jaLYaku45dnSdwCTM3Q0LTTxcxY+kgkOxY36pu0Fv90\n" +
                "N+pKVXaTHI72CeP2BgRGziw55JEfuY/MbIaJTGIe1OfI7ns992ZTXyiudCePCqm2\n" +
                "zp/6+7dO/mL11n40j9jwQ36OEJmefxMm2B3G0VmQTxASqvWBrQ5IR88IJAryny+r\n" +
                "4zPV3NvI2nZKQCQL/wGFAMq0gIML5uEGEbmprHYs5OiE/c+GbvOXm+UpO7glSjUw\n" +
                "raZT+JCbEy1abseZ17nhr4vaiFfxg+Q6qX6j8WkpT/bxzDedqmuzZPKN1gbHFTEa\n" +
                "cuar6mnA2n1OeXEWt779px5Fw3AxMM0/D/++5iKX+kMInQdGBGarnigBEADUilhf\n" +
                "fvmqbvgDAPAfkGHOIgHv9wQVWBBahTWfyXU7vK+xNfy3gwMHzcEl68reRb2B52TY\n" +
                "zzrnLbcGxt+KUhaUxGWekoW7kI6XhAS74RCPos3NVdtPIiASyB8eB8X9LEI85izI\n" +
                "yNEQaDIDWKXpe19bIjvo7ptCmSTYjy/tTQ7TyjXyySGcF7n6ezKcSxDM50F47p+s\n" +
                "hsSemPacdlmOVHM3VSCMgjD6Z+exNj5O4ZE0RMCUlGe6tZtX2lD1NwUQGFXfWUBM\n" +
                "yAks2QtXkP9VF2h1gG+6GH+zQ5ZPSPxJ4jHd5vnGbcLJK9jvdEAbi+xj/XVL4cBg\n" +
                "d0VXYx2Da8x010O1bJySsaLbFOyyQ8eUZSKpihWYHUJEWQAgKLXM/uZ1q3pOmsis\n" +
                "cM41aJcG/vdx30ZnBIq35qRjxuRAcwp69I2vknJ8S+DtZ9nifVFqcVZKMfeDgg65\n" +
                "NdW1Jd3EHhxKnFwDok5575iuzidUiOzwuWpOEYTVK1YlRPtgZcpkcVm2oeRY2eNE\n" +
                "uYge8YCsBgGL1RvikZKzYQAJc0v6J8FUz90YAnefIleA+PQAiM5N/GYdb1qoUr1u\n" +
                "m8w3Pfj6o5xXMl/2YKXYKONK4I+sib22I4U73MeUdhzoy4KorA5vVZLzc2Y2UXT7\n" +
                "niSOQVGBKJ9rkWmLzIwItyD2Nv9lEH2+QElSWQARAQAB/gcDAkr3tI02kpxX+vvS\n" +
                "OJku+Ecct6DfuuE+JqRlBg7LSJDDH0EenUhPYM9hu2yj5K6zyVPo+h3MWILMsk10\n" +
                "aECY8O0fupbw7S4Vd+H/JvA15wWctCg9hoCJDyQoaeg9TkaG+xdXA84JuZpjv8x7\n" +
                "urXIvmc4HKnWK1pnO67DI5i/ZVAJFjnthlwOcrPp1Uo3MO1OAVJy3oN9Fz8GLzbT\n" +
                "FN66o78iyMp7qw9nQbDstkJldCk1+6POQBXkzGRAwaFbVWyNyYUuhF9Iad/y4zjP\n" +
                "XJKk5I+I6B5lcV4g7O1Mz2Bkwpw/6PxdkgYoFfM9R2YlxFdwkt9asZnXek5rvhbo\n" +
                "OMF9/davw+asq5A8FliDfb3Vqn9bgXcYxVsgp9yM6TrMbNQGBWA2j42J2I3w8pR8\n" +
                "bkdB53ZJ2w7R83olG69h3IX3sHFG+ojWz6pTMgnq82supV3IV0ygCJHhSRQ4qcZh\n" +
                "I3Nwjgd+zZW6xbDzfwXwEGvwfX5bniKnvXsZQ88t2KBfDnKbIYw/L4qFoX+7M7rW\n" +
                "SnQBI+Poda3NEIz7wY0cxUEScZMo46ksCNde2FaA8EX1C1RRcsO3WF4+RNizZQfD\n" +
                "dpTeYn9K6VuXm6uGqap/iVtl4W0f9WEwMLeBfy49DJr2UT1zvu/O5sY7q8KglBR5\n" +
                "6HVnd764c9BLYSmnMFMS2HHG6W1K1/R3+dY7mjc3daKS0j3gLU8Mm0Djfk+OGweI\n" +
                "xCrhw50IAQiF8e7sIfjKMTP4DsK98da0NgQtOvJw0DMjW4vSPaUsUE6rDIV0/RQ8\n" +
                "X8aBdJ70Tbe+fQmpvPsU9ERJXzoHzOmxWTi2enZ/xnjJqIHZDsmb/LqHXml5WusP\n" +
                "lTFGm+UOm6vztXYBDe+q2PcgOWdiyQgl7qD1cis2Cz6DMp1OFpy1JpoP9EOoO5on\n" +
                "el2oENDBOEek4NT925Qb9XqZVu8B08zDgiYmAVEQPFe6V8pCUzB2vfpBGdP/9sNI\n" +
                "c3z2oHF4eeOMRdRmXgEoJ+skF53lCQ7SmnAXoiKK4JH+2pVDloQrdLNruTBKlsZY\n" +
                "LlPJEdTqSKVJkffTORjnR0PYDIP7P20CJBPhBLUkm1sP5fVXt9b4rT/9YFL5FiN4\n" +
                "zyA4YxJd2sxU6wIHJj5fT8HQ3YBNn3CqbpotCNdn+CYbDO0zvdnfAPp67Mzq+QLB\n" +
                "Oqe0Or2kp1WLzOTGIzXXM74JnOnsSXxyo5cARiEJ/T1FkAzy/BFpRmUBOpM2Gq+g\n" +
                "j1u+/BUWzi/fquGNfRnoaYh9qhWHockvtn08JjXYj81EsEmH0rwOci1BV4iSKoYz\n" +
                "hkzBgsAOIF2JF/7IdRdpT5GYkACl23Xo2gAF02bBwjmB6cdJorwibGa05Bqmin+l\n" +
                "z0yzvq9EssBTNsAxaz0H4igWUoti/y2gzTz4aomdSm06ORkYL4Sdr4+sur6tYrRJ\n" +
                "ruaUfBNSkhql+tFUoLkr2Swq7q77nbqQUlTiuwnzHT5BOmpicOs7BqJ2Hdhlm0zW\n" +
                "cHOc8lz4e/E9Q2rRjYGkHr/ynZkF/c5fSYxum2KK1kfNGMrc9x1ye6xlKf08DmIW\n" +
                "Tba8rd1lvUNTEMOA7nhDoPQEiN8QVEEutnRT12GkP5zZmXvQl8K9FKcFhDUcBH7Y\n" +
                "MX5fpwdI+MKwcGWnJ8Sn1cfjhlqj/xtApMBKgdAPIEHNwvAFGK6xKCOhRLY5a8bc\n" +
                "X2h81GCYrX8h9VkXN3EeWNDj5hmqadgBSZozjgSq3TgO5JVzjfm1Vqqh5yDAqm45\n" +
                "I00xByDNdoojyM8mGjS9QfXfDMGiycvidQ6JAjwEGAEIACYWIQRV9Zi2Bvb5b2Nj\n" +
                "zSCs67+newEikgUCZqueKAIbDAUJBaOagAAKCRCs67+newEiktzzEACk9WycGEir\n" +
                "ftjUFGs8WgqaXbIpylaSSXZAa6YhMKLJrQCZzjzuY+aHxWmOtgNdpD5w/OuoP07y\n" +
                "QWKtbpEOIFDcYrN3Nfpt/ih9GHpgJUk4tJGp+eyE6Jejhwv1u4sDKdl8PiEow3mu\n" +
                "368PM82RzUP+Fti0IsTNRJ8tPRBzw9TTCebbpUi8tC1DQaqGDh8HngjkM6E39v8S\n" +
                "DPfU1zzcoXFDPg6NvsZMDM0wEbSPFp+JJOH76N5FgNUA9q0h4qqiANK9VxeoLlzO\n" +
                "FaSThjUq2aCkWYYe9GO2QEfJxosAKxt8FNs4pT7vdbIcQgOBwcagEZ3jNN8qx7sJ\n" +
                "92JRwcBYcvvzpzZvVfsSxZqOy5KaeInJoP7EH0Zml8KOpGDWvgu1dnQf+vwMI2Fg\n" +
                "AAH6dUAAY3mOQzXkd2ctl4uR8AZLuXDJKncFLKIohrZe+ADut0h6kNNbkJL9nxot\n" +
                "BxGhGgJo9uG2cYTIzwqb8S4AzUxDP7fWCRSynZo2Ff08H97lnMuMBWtJzjuTsCOH\n" +
                "oW0P87lEd8dIqx0/H4HUty6cQfXHHtNbHb2lZf8BcqlpYA9GlBGqN5vQtu9mJCfk\n" +
                "Az3OqX2csL4xQ1GTEfpnoX35D+foKRM4tX3k7cvqdJ0lBtS9JuZ7GrAlbJJ3ibnC\n" +
                "GPIHTrgIxIckMWsuOC9On+eseDnp7uRcMw==\n" +
                "=fJnD\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        PGPSecretKeyRing secretKey = PGPainless.readKeyRing()
                .secretKeyRing(key);

        assert secretKey != null;
        String armored = PGPainless.asciiArmor(secretKey);
        ByteArrayOutputStream binary = new ByteArrayOutputStream();
        secretKey.encode(binary);

        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);
        System.out.println(certificate.getEncoded());
    }


    @Test
    void generateKeyAlice() throws IOException {
        SOP sop = new SOPImpl();
        Ready secretKey = sop.generateKey()
                .userId("Alice <alice@gmail.com>")
//                .profile("draft-koch-eddsa-for-openpgp-00")
                .profile("rfc4880")
                .withKeyPassword("alice123")
                .generate();
        System.out.println("Secret Key");
        FileOutputStream privateKeyFile = new FileOutputStream(path + "alice_private_key.asc");

        secretKey.writeTo(privateKeyFile);
        privateKeyFile.close();

        System.out.println("Public Key");
        FileOutputStream publicKeyFile = new FileOutputStream(path + "alice_public_key.asc");
        sop.extractCert()
                .key(secretKey.getBytes())
//                .writeTo(System.out);
                .writeTo(publicKeyFile);
        publicKeyFile.close();
    }

    @Test
    void generateKeyBob() throws IOException {
        SOP sop = new SOPImpl();
        Ready secretKey = sop.generateKey()
                .userId("Bob <bob@gmail.com>")
                .profile("rfc4880")
                .withKeyPassword("bob123")
                .generate();
        System.out.println("Secret Key");
        FileOutputStream privateKeyFile = new FileOutputStream(path + "bob_private_key.asc");

        secretKey.writeTo(privateKeyFile);
        privateKeyFile.close();

        System.out.println("Public Key");
        FileOutputStream publicKeyFile = new FileOutputStream(path + "bob_public_key.asc");
        sop.extractCert()
                .key(secretKey.getBytes())
//                .writeTo(System.out);
                .writeTo(publicKeyFile);
        publicKeyFile.close();
    }


    @Test
    void generateKey() throws IOException {
        SOP sop = new SOPImpl();
        Ready secretKey = sop.generateKey()
                .userId("Rajeshkumar <rajeshmepco@gmail.com>")
                .profile("draft-koch-eddsa-for-openpgp-00")
                .withKeyPassword("Ganeshh12#")
                .generate();
        System.out.println("Secret Key");
        secretKey.writeTo(System.out);

        System.out.println("Public Key");
        sop.extractCert()
                .key(secretKey.getBytes())
                .writeTo(System.out);
    }

    @Test
    void listProfiles() {
        SOP sop = new SOPImpl();
        List<Profile> profiles = sop.listProfiles().subcommand("generate-key");
        System.out.println(profiles);
    }


    @Test
    void changePasswordOfSecret() throws IOException {
        SOP sop = new SOPImpl();

        Ready secretKey = sop.generateKey()
                .userId("Rajeshkumar <rajeshkumar@gmail.com>")
                .profile("draft-koch-eddsa-for-openpgp-00")
                .withKeyPassword("Ganeshh12#")
                .withKeyPassword("secondpassword")
                .generate();
        System.out.println("Secret Key");
        secretKey.writeTo(System.out);

        sop.changeKeyPassword()
                // Provide old passphrases - all subkeys need to be decryptable,
                //  otherwise KeyIsProtected exception will be thrown
                .oldKeyPassphrase("Ganeshh12#")
                .oldKeyPassphrase("secondpassword")
                // Provide the new passphrase - if omitted, key will be unprotected
                .newKeyPassphrase("rajeshkumar")
                .keys(secretKey.getBytes())
                .writeTo(System.out);
    }

    @Test
    void revokeKey() throws IOException {


        SOP sop = new SOPImpl();
        Ready secretKey = sop.generateKey()
                .userId("Rajeshkumar <rajeshmepco@gmail.com>")
                .profile("draft-koch-eddsa-for-openpgp-00")
                .withKeyPassword("Ganeshh12#")
                .generate();
        System.out.println("Secret Key");
        FileOutputStream privateKeyFile = new FileOutputStream(path + "private_key.asc");

        secretKey.writeTo(privateKeyFile);
        privateKeyFile.close();

        System.out.println("Public Key");
        FileOutputStream publicKeyFile = new FileOutputStream(path + "public_key.asc");


        sop.extractCert()
                .key(secretKey.getBytes())
//                .writeTo(System.out);
                .writeTo(publicKeyFile);
        publicKeyFile.close();

        System.out.println("Revoke Key");
        FileOutputStream revokeKeyFile = new FileOutputStream(path + "revoke_key.asc");
        sop.revokeKey()
                // primary key password(s) if the key(s) are protected
                .withKeyPassword("Ganeshh12#")
                // one or more secret keys
                .keys(secretKey.getBytes())
//                .writeTo(System.out);
                .writeTo(revokeKeyFile);
        revokeKeyFile.close();
    }

    @Test
    void generateKeyNoArmor() throws IOException {
        SOP sop = new SOPImpl();
        Ready secretKey = sop.generateKey()
                .userId("Rajeshkumar <rajeshkumar@gmail.com>")
                .profile("draft-koch-eddsa-for-openpgp-00")
                .withKeyPassword("Ganeshh12#")
                .withKeyPassword("secondpassword")
                .noArmor()
                .generate();
        System.out.println("Secret Key");
        FileOutputStream noArmorKey = new FileOutputStream(path + "secret_key_binary.asc");
        secretKey.writeTo(noArmorKey);
        noArmorKey.close();

        FileInputStream binaryKeyFile = new FileInputStream(path + "secret_key_binary.asc");
        FileOutputStream binaryToASCIIKeyFile = new FileOutputStream(path + "secret_key_binary_to_ascii.asc");

        sop.armor()
                .data(binaryKeyFile)
                .writeTo(binaryToASCIIKeyFile);
        binaryKeyFile.close();
        binaryToASCIIKeyFile.close();


    }

    @Test
    void encryptAndDecrypt() throws IOException {
        long startTime1 = System.currentTimeMillis();
        System.out.println(startTime1);
        try (FileInputStream aliceKey = new FileInputStream(path + "alice_private_key.asc");
             FileInputStream aliceCert = new FileInputStream(path + "alice_public_key.asc");
             FileInputStream plainMessage = new FileInputStream(path + "plain_message.json");
             FileOutputStream decryptedMessage = new FileOutputStream(path + "decrypted_message.json");
             FileOutputStream encryptedFile = new FileOutputStream(path + "encrypted_message.asc");
             FileInputStream bobKey = new FileInputStream(path + "bob_private_key.asc");
             FileInputStream bobCert = new FileInputStream(path + "bob_public_key.asc");
        ) {
            long startTime2 = System.currentTimeMillis();
            System.out.println(startTime2);
//            byte[] plainText = plainMessage.getBytes();
            SOP sop = new SOPImpl();
            Ready ready = sop.encrypt()
                    // encrypt for each recipient
                    .withCert(bobCert)
//                    .withCert(aliceCert)
                    // Optionally: Sign the message
//                    .signWith(aliceKey)
//                    .withKeyPassword("alice123") // if signing key is protected
                    // provide the plaintext
                    .plaintext(plainMessage);
            ready.writeTo(encryptedFile);
            encryptedFile.close();
            FileInputStream encryptedFileToRead = new FileInputStream(path + "encrypted_message.asc");
            ReadyWithResult<DecryptionResult> readyWithResult = sop.decrypt()
                    .withKey(bobKey)
//                    .verifyWithCert(aliceCert)
                    .withKeyPassword("bob123") // if decryption key is protected
                    .ciphertext(encryptedFileToRead);
//            ByteArrayAndResult<DecryptionResult> bytesAndResult = readyWithResult.toByteArrayAndResult();
//            DecryptionResult result = bytesAndResult.getResult();
//            byte[] plaintext = bytesAndResult.getBytes();
//            System.out.println(plaintext);
            readyWithResult.writeTo(decryptedMessage);
//            readyWithResult.writeTo(System.out);
            long startTime3 = System.currentTimeMillis();
            System.out.println(startTime3);
            System.out.println(startTime3-startTime2);

            /*
            SOP sop = new SOPImpl();
            Ready encryptedMessage = sop.encrypt()
                    .withCert(bobCert)
                    .plaintext(plainText);

            encryptedMessage.writeTo(encryptedFile);

            ReadyWithResult<DecryptionResult> decryptedMessage = sop.decrypt()
                    .withKey(bobKey)
                    .withPassword("bob123")
                    .ciphertext(encryptedMessage.getBytes());

            decryptedMessage.writeTo(System.out);
            */
        }
    }


    @Test
    void encryptAndDecrypt2() throws IOException {
        FileInputStream bobKey = new FileInputStream(path + "bob_private_key.asc");
        FileInputStream bobCert = new FileInputStream(path + "bob_public_key.asc");
        FileInputStream aliceKey = new FileInputStream(path + "alice_private_key.asc");
        FileInputStream aliceCert = new FileInputStream(path + "alice_public_key.asc");
        SOP sop = new SOPImpl();
        byte[] plainText = "Hello World!".getBytes();
        Ready encryptedMessage = sop.encrypt()
                .withCert(bobCert)
                .withCert(aliceCert)
                .signWith(aliceKey)
                .withKeyPassword("alice123")
                .plaintext(plainText);
        FileOutputStream encryptedMessageFile = new FileOutputStream(path + "simple_encrypted_file.asc");
        encryptedMessage.writeTo(encryptedMessageFile);

        FileInputStream encryptedMessageFile1 = new FileInputStream(path + "simple_encrypted_file.asc");

        FileInputStream aliceCert2 = new FileInputStream(path + "alice_public_key.asc");

        ReadyWithResult<DecryptionResult> decryptedMessage1 = sop.decrypt()
                .withKey(bobKey)
                .verifyWithCert(aliceCert2)
                .withKeyPassword("bob123")
                .ciphertext(encryptedMessageFile1);
        decryptedMessage1.writeTo(System.out);

        FileInputStream aliceKey2 = new FileInputStream(path + "alice_private_key.asc");
        FileInputStream encryptedMessageFile2 = new FileInputStream(path + "simple_encrypted_file.asc");
        ReadyWithResult<DecryptionResult> decryptedMessage2 = sop.decrypt()
                .withKey(aliceKey2)
                .withKeyPassword("alice123")
                .ciphertext(encryptedMessageFile2);

        decryptedMessage2.writeTo(System.out);

    }


}