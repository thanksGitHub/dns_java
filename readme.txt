this is a simple dns


import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class DNSTest {


    static Logger log = Logger.getLogger("DNSd");

    static ConcurrentHashMap<Integer, byte[]> resolved = new ConcurrentHashMap<>();

    static byte[] defaultIp = ByteBuffer.allocate(4)
            .putInt(ipToInt("xxxxxxx")).array();


    public static void main(String args[]) {

        String host = "xx.xxxx.xxx";

        int dnsPort = 53;
        try (DatagramSocket serverSocket = new DatagramSocket(dnsPort)) {
            byte[] receiveData = new byte[512];
            log.info("DNSd started at :" + dnsPort);
            while (true) {
                try {

                    DatagramPacket receivePacket = new DatagramPacket(
                            receiveData, receiveData.length);
                    serverSocket.receive(receivePacket);

                    StringBuilder qname = new StringBuilder();
                    int idx = 12;// skip
                    // transaction/id/flags/questions/answer/authority/additional
                    int len = receiveData[idx];
                    while (len > 0) {
                        qname.append(".").append(
                                new String(receiveData, idx + 1, len));
                        idx += len + 1;
                        len = receiveData[idx];
                    }
                    if (qname.length() > 0) {
                        String name = qname.substring(1).toLowerCase();
                        int type = receiveData[idx + 1] * 256
                                + receiveData[idx + 2];
                        log.info(receivePacket.getAddress() + ":"
                                + receivePacket.getPort() + "\t" + name + "\t"
                                + type);

                        if ((!name.equals(host))
                                && (!name.endsWith("." + host))) {
                            continue;// keep silence
                        }
                        if (type != 1 && !name.equals(host)) {
                            continue;// we only response for A records, except
                            // for MX
                            // for host
                        }

                        ByteArrayOutputStream bo = new ByteArrayOutputStream();
                        bo.write(new byte[]{receiveData[0], receiveData[1],
                                (byte) 0x81, (byte) 0x80, 0x00, 0x01, 0x00,
                                0x01, 0x00, 0x00, 0x00, 0x00});
                        // write query
                        byte[] req = Arrays.copyOfRange(receiveData, 12,
                                idx + 5);
                        bo.write(req);

                        //write answer
                        bo.write(req);
                        bo.write(ByteBuffer.allocate(4)
                                .putInt(name.equals(host) ? 3600 : 10).array());// ttl，ttl
                        if (type == 1) {
                            bo.write(new byte[]{0x00, 0x04});
                            int val = bytesToInt(receivePacket.getAddress()
                                    .getAddress());
                            bo.write((!name.equals(host))
                                    && resolved.containsKey(val) ? resolved
                                    .get(val) : defaultIp);


                        } else {// for MX
                            String mx = "mxdomain.qq.com";
                            bo.write(ByteBuffer.allocate(2)
                                    .putShort((short) (mx.length() + 4))
                                    .array());
                            bo.write(0x00);
                            bo.write(0x05);// preference
                            for (String s : mx.split("\\.")) {
                                bo.write((byte) s.length());
                                bo.write(s.getBytes());
                            }
                            bo.write(0x00);
                        }

                        byte[] sendData = bo.toByteArray();
                        DatagramPacket sendPacket = new DatagramPacket(
                                sendData, sendData.length,
                                receivePacket.getAddress(),
                                receivePacket.getPort());
                        serverSocket.send(sendPacket);

                    }

                } catch (Exception e) {
                    log.warning(e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warning(e.getMessage());
        }
    }


    // ip string byte[] converts
    private static int ipToInt(String ipAddress) {
        long result = 0;
        String[] ipAddressInArray = ipAddress.split("\\.");
        for (int i = 3; i >= 0; i--) {
            long ip = Long.parseLong(ipAddressInArray[3 - i]);
            result |= ip << (i * 8);
        }
        return (int) result;
    }

    private static byte[] ipToBytes(String ip) {
        return ByteBuffer.allocate(4).putInt(ipToInt(ip)).array();
    }

    private static String intToIp(int i) {
        return ((i >> 24) & 0xFF) + "." + ((i >> 16) & 0xFF) + "."
                + ((i >> 8) & 0xFF) + "." + (i & 0xFF);
    }

    private static int bytesToInt(byte[] bytes) {
        int val = 0;
        for (int i = 0; i < bytes.length; i++) {
            val <<= 8;
            val |= bytes[i] & 0xff;
        }
        return val;
    }

    private static String bytesToIp(byte[] bytes) {
        return ((bytes[0]) & 0xFF) + "." + ((bytes[1]) & 0xFF) + "."
                + ((bytes[2]) & 0xFF) + "." + (bytes[3] & 0xFF);
    }

}
