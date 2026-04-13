package dev.ysdaeth.keystore;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;

final class SecureKeyEntrySerializer {
    private static final Map<String, BiConsumer<String, SecuredKeyEntry.Builder>> dynamicSetter = new HashMap<>();
    static{
        dynamicSetter.put("ALIAS", (val,b)->b.alias(val));
        dynamicSetter.put("ALG", (val,b)->b.keyAlg(val));
        dynamicSetter.put("KEY", (val,b)->b.key(Base64.getDecoder().decode(val)) );
        dynamicSetter.put("PUB-KEY", (val,b)->b.pubKey(Base64.getDecoder().decode(val)) );
        dynamicSetter.put("KDF-ALG",(val,b)->b.derivationAlg(val));
        dynamicSetter.put("KDF-PARAM", (val,b)->b.addKdfParam( parseProtectionEntry(val) ));
    }

    static String serialize(SecuredKeyEntry entry){
        String key = Base64.getEncoder().encodeToString(entry.key());
        String pubKey = entry.pubKey() == null? null : Base64.getEncoder().encodeToString(entry.pubKey());
        StringBuilder builder = new StringBuilder();
        builder.append("ALIAS:").append(entry.alias());
        builder.append('\n').append("ALG:").append(entry.keyAlg());
        builder.append('\n').append("KEY:").append(key);
        if(pubKey !=null ) builder.append('\n').append("PUB-KEY:").append(pubKey);
        builder.append('\n').append("KDF-ALG:").append(entry.kdfAlg());

        for(Map.Entry<String,String> mapEntry: entry.kdfParams().entrySet()){
            String param = mapEntry.getKey();
            String arg = mapEntry.getValue();
            builder.append('\n').append("KDF-PARAM:").append(param).append('=').append(arg);
        }
        return builder.toString();
    }

    static SecuredKeyEntry deserialize(String serialized) {
        SecuredKeyEntry.Builder secureEntry = new SecuredKeyEntry.Builder();

        String[] lines = serialized.split("\n");
        for(int i = 0; i< lines.length; i++){
            String[] tagValue = parseTag(lines[i]);
            String tag = tagValue[0];
            String value = tagValue[1];
            dynamicSetter.get(tag).accept(value, secureEntry);
        }

        return secureEntry.build();
    }

    private static String[] parseTag(String line){
        int index = line.indexOf(":");
        String tag = line.substring(0,index);
        String value = line.substring(index + 1);
        return new String[]{tag, value};
    }

    private static Map.Entry<String,String> parseProtectionEntry(String line) {
        int index = line.indexOf('=');
        String key = line.substring(0,index);
        String val = line.substring(index + 1);
        return Map.entry(key,val);
    }
}
