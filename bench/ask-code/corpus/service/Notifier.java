package demo.service;

public class Notifier {
    /** Send a text message to every subscribed phone of a user. */
    public int pushToDevices(User user, String body) {
        int sent = 0;
        for (Device d : user.devices) {
            if (d.subscribed) {
                gateway.deliver(d.token, body);
                sent++;
            }
        }
        return sent;
    }
}
