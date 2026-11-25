package com.ditz.adshield;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class AdShieldVpnService extends VpnService {
    public interface Listener {
        void update(boolean on, long blocked, long allowed);
    }

    private static Listener listener;
    private static volatile boolean running = false;
    private static final AtomicLong blocked = new AtomicLong();
    private static final AtomicLong allowed = new AtomicLong();

    private static final String VPN_IP = "10.111.0.1";
    private static final String DNS_IP = "10.111.0.2";

    private ParcelFileDescriptor tun;
    private Thread worker;
    private final AtomicBoolean stop = new AtomicBoolean(false);

    // Conservative starter list. False positives are possible; expand only with verified hosts.
    private static final Set<String> BLOCK = new HashSet<>(Arrays.asList(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "adservice.google.com", "pagead2.googlesyndication.com",
        "googletagmanager.com", "adnxs.com", "adsrvr.org", "adform.net",
        "adcolony.com", "applovin.com", "unityads.unity3d.com", "unity3d.com",
        "ironsrc.com", "vungle.com", "liftoff.io", "mintegral.com", "mbridge.com",
        "pangle.io", "bytedance.com", "amazon-adsystem.com", "criteo.com",
        "criteo.net", "taboola.com", "outbrain.com", "inmobi.com", "yandex.ru",
        "mc.yandex.ru", "smartadserver.com", "rubiconproject.com",
        "pubmatic.com", "openx.net", "adsterra.com", "popads.net",
        "propellerads.com", "exoclick.com", "trafficjunky.com"
    ));

    public static void setListener(Listener value) {
        listener = value;
        notifyListener();
    }

    public static boolean isRunning() {
        return running;
    }

    public static long getBlockedCount() {
        return blocked.get();
    }

    public static long getAllowedCount() {
        return allowed.get();
    }

    private static void notifyListener() {
        Listener current = listener;
        if (current != null) {
            current.update(running, blocked.get(), allowed.get());
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (running) return START_STICKY;

        createNotification();
        try {
            Builder builder = new Builder()
                .setSession("DiTz AdShield")
                .setMtu(1500)
                .addAddress(VPN_IP, 32)
                .addDnsServer(DNS_IP)
                .addRoute(DNS_IP, 32);

            tun = builder.establish();
            if (tun == null) {
                throw new IllegalStateException("VPN interface could not be established");
            }

            stop.set(false);
            running = true;
            notifyListener();
            worker = new Thread(this::packetLoop, "DiTz-DNS-Filter");
            worker.start();
        } catch (Exception error) {
            running = false;
            notifyListener();
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
        }
        return START_STICKY;
    }

    private void createNotification() {
        String channelId = "ditz_adshield";
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                channelId, "DiTz AdShield", NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.createNotificationChannel(channel);
        }

        Notification notification = new Notification.Builder(this, channelId)
            .setContentTitle("DiTz AdShield aktif")
            .setContentText("DNS filtering untuk semua aplikasi sedang berjalan")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build();
        startForeground(77, notification);
    }

    private void packetLoop() {
        try {
            FileInputStream input = new FileInputStream(tun.getFileDescriptor());
            FileOutputStream output = new FileOutputStream(tun.getFileDescriptor());
            byte[] buffer = new byte[32767];

            while (!stop.get()) {
                try {
                    int count = input.read(buffer);
                    if (count <= 0) continue;

                    byte[] packet = Arrays.copyOf(buffer, count);
                    byte[] response = handle(packet);
                    if (response != null) {
                        synchronized (output) {
                            output.write(response);
                        }
                    }
                } catch (IOException error) {
                    if (!stop.get()) break;
                } catch (RuntimeException ignored) {
                    // Drop malformed packet; keep the VPN service alive.
                }
            }
        } finally {
            running = false;
            closeTun();
            notifyListener();
            stopSelf();
        }
    }

    private byte[] handle(byte[] packet) {
        if (packet.length < 28 || ((packet[0] >> 4) & 15) != 4 ||
            (packet[9] & 255) != 17) {
            return null;
        }

        int ipHeaderLength = (packet[0] & 15) * 4;
        if (ipHeaderLength < 20 || packet.length < ipHeaderLength + 8) {
            return null;
        }

        int destinationPort = u16(packet, ipHeaderLength + 2);
        if (destinationPort != 53) return null;

        int dnsOffset = ipHeaderLength + 8;
        if (packet.length - dnsOffset < 12) return null;

        byte[] query = Arrays.copyOfRange(packet, dnsOffset, packet.length);
        String domain = readDomain(query);
        boolean denied = isBlocked(domain);

        byte[] answer;
        if (denied) {
            blocked.incrementAndGet();
            answer = makeNxDomain(query);
        } else {
            allowed.incrementAndGet();
            answer = forward(query);
            if (answer == null) answer = makeServFail(query);
        }

        notifyListener();
        return buildUdpResponse(packet, ipHeaderLength, answer);
    }

    private byte[] forward(byte[] dns) {
        for (String host : new String[]{"1.1.1.1", "8.8.8.8"}) {
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setSoTimeout(2600);
                InetAddress resolver = InetAddress.getByName(host);
                DatagramPacket request = new DatagramPacket(
                    dns, dns.length, new InetSocketAddress(resolver, 53)
                );
                socket.send(request);

                byte[] buffer = new byte[4096];
                DatagramPacket response = new DatagramPacket(buffer, buffer.length);
                socket.receive(response);
                return Arrays.copyOf(response.getData(), response.getLength());
            } catch (Exception ignored) {
                // Try the next resolver.
            }
        }
        return null;
    }

    private static String readDomain(byte[] dns) {
        try {
            int index = 12;
            StringBuilder domain = new StringBuilder();
            while (index < dns.length) {
                int length = dns[index++] & 255;
                if (length == 0) break;
                if ((length & 0xC0) != 0 || length > 63 || index + length > dns.length) {
                    return "";
                }
                if (domain.length() > 0) domain.append('.');
                domain.append(new String(dns, index, length, StandardCharsets.US_ASCII));
                index += length;
            }
            return domain.toString().toLowerCase(Locale.ROOT);
        } catch (RuntimeException error) {
            return "";
        }
    }

    private static boolean isBlocked(String domain) {
        if (domain.isEmpty()) return false;
        for (String blockedDomain : BLOCK) {
            if (domain.equals(blockedDomain) || domain.endsWith("." + blockedDomain)) {
                return true;
            }
        }
        return false;
    }

    private static byte[] makeNxDomain(byte[] query) {
        byte[] response = Arrays.copyOf(query, query.length);
        response[2] = (byte) 0x81;
        response[3] = (byte) 0x83;
        clearDnsAnswerCounts(response);
        return response;
    }

    private static byte[] makeServFail(byte[] query) {
        byte[] response = Arrays.copyOf(query, query.length);
        response[2] = (byte) 0x81;
        response[3] = (byte) 0x82;
        clearDnsAnswerCounts(response);
        return response;
    }

    private static void clearDnsAnswerCounts(byte[] dns) {
        dns[6] = 0; dns[7] = 0;
        dns[8] = 0; dns[9] = 0;
        dns[10] = 0; dns[11] = 0;
    }

    private static byte[] buildUdpResponse(byte[] request, int ipHeaderLength, byte[] dns) {
        int totalLength = 20 + 8 + dns.length;
        byte[] response = new byte[totalLength];

        response[0] = 0x45;
        response[2] = (byte) (totalLength >> 8);
        response[3] = (byte) totalLength;
        response[4] = request[4];
        response[5] = request[5];
        response[6] = 0x40;
        response[8] = 64;
        response[9] = 17;

        System.arraycopy(request, 16, response, 12, 4);
        System.arraycopy(request, 12, response, 16, 4);

        response[20] = request[ipHeaderLength + 2];
        response[21] = request[ipHeaderLength + 3];
        response[22] = request[ipHeaderLength];
        response[23] = request[ipHeaderLength + 1];

        int udpLength = 8 + dns.length;
        response[24] = (byte) (udpLength >> 8);
        response[25] = (byte) udpLength;
        System.arraycopy(dns, 0, response, 28, dns.length);

        int headerChecksum = checksum(response, 0, 20);
        response[10] = (byte) (headerChecksum >> 8);
        response[11] = (byte) headerChecksum;
        return response;
    }

    private static int checksum(byte[] data, int offset, int length) {
        long sum = 0;
        for (int index = offset; index < offset + length; index += 2) {
            sum += ((data[index] & 255) << 8) |
                (index + 1 < offset + length ? (data[index + 1] & 255) : 0);
        }
        while ((sum >> 16) != 0) sum = (sum & 65535) + (sum >> 16);
        return (int) (~sum) & 65535;
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 255) << 8) | (data[offset + 1] & 255);
    }

    @Override
    public void onRevoke() {
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stop.set(true);
        running = false;
        closeTun();
        notifyListener();
        super.onDestroy();
    }

    private void closeTun() {
        try {
            if (tun != null) {
                tun.close();
                tun = null;
            }
        } catch (IOException ignored) {
            // Already closed.
        }
    }
}
