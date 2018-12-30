package org.zeromq.codec;

public final class Z85
{
    private Z85()
    {
    }

    public static byte[] ENCODER = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                    'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '.', '-',
                                    ':', '+', '=', '^', '!', '/', '*', '?', '&', '<', '>', '(', ')', '[', ']', '{', '}', '@', '%', '$', '#', '0' };

    public static byte[] DECODER = { 0x00, 0x44, 0x00, 0x54, 0x53, 0x52, 0x48, 0x00, 0x4B, 0x4C, 0x46, 0x41, 0x00, 0x3F, 0x3E, 0x45, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x40,
                                    0x00, 0x49, 0x42, 0x4A, 0x47, 0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                                    0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x4D, 0x00, 0x4E, 0x43, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                                    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x4F, 0x00, 0x50, 0x00, 0x00 };

    /**
     * Encode a binary frame as a string using Z85 encoding;
     * @param data
     * @return
     */
    public static String Z85Encoder(byte[] data)
    {
        if (data == null || data.length % 4 != 0) {
            return null;
        }
        int size = data.length;
        int char_nbr = 0;
        int byte_nbr = 0;
        long value = 0;
        byte[] dest = new byte[size * 5 / 4];
        while (byte_nbr < size) {
            // Accumulate value in base 256 (binary)
            value = value * 256 + (data[byte_nbr++] & 0xFF); // Convert signed
                                                             // byte to int
            if (byte_nbr % 4 == 0) {
                // Output value in base 85
                long divisor = 85 * 85 * 85 * 85;
                while (divisor > 0) {
                    int index = (int) (value / divisor % 85);
                    dest[char_nbr++] = ENCODER[index];
                    divisor /= 85;
                }
                value = 0;
            }
        }
        return new String(dest);
    }

    public static byte[] Z85Decoder(String string)
    {
        // Accepts only strings bounded to 5 bytes
        if (string == null || string.length() % 5 != 0)
            return null;

        int decoded_size = string.length() * 4 / 5;
        byte[] decoded = new byte[decoded_size];

        int byte_nbr = 0;
        int char_nbr = 0;
        long value = 0;
        while (char_nbr < string.length()) {
            // Accumulate value in base 85
            value = value * 85 + DECODER[(byte) string.charAt(char_nbr++) - 32];
            if (char_nbr % 5 == 0) {
                // Output value in base 256
                long divisor = 256 * 256 * 256;
                while (divisor > 0) {
                    decoded[byte_nbr++] = (byte) (value / divisor % 256);
                    divisor /= 256;
                }
                value = 0;
            }
        }
        return decoded;
    }
}
