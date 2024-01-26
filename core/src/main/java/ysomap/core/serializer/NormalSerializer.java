package ysomap.core.serializer;

public class NormalSerializer extends BaseSerializer<byte[]>{
    @Override
    public byte[] serialize(Object obj) throws Exception {
        return new byte[0];
    }

    @Override
    public Object deserialize(byte[] obj) throws Exception {
        return null;
    }

    @Override
    public String getOutputType() {
        return null;
    }

    @Override
    public void setOutputType(String output) {

    }
}
