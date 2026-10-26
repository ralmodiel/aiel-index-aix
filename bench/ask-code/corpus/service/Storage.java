package demo.service;

public class Storage {
    /** Upload an image to the bucket and return its public address. */
    public String putImage(byte[] data, String name) {
        String key = "images/" + name;
        s3.putObject(bucket, key, data);
        return cdnBase + "/" + key;
    }

    /** Remove a stored file from the bucket. */
    public void removeImage(String key) {
        s3.deleteObject(bucket, key);
    }
}
