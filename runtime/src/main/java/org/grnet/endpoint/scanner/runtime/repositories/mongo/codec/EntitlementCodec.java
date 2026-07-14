package org.grnet.endpoint.scanner.runtime.repositories.mongo.codec;

import com.mongodb.MongoClientSettings;
import org.bson.BsonReader;
import org.bson.BsonString;
import org.bson.BsonValue;
import org.bson.BsonWriter;
import org.bson.Document;
import org.bson.codecs.Codec;
import org.bson.codecs.CollectibleCodec;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.EncoderContext;
import org.bson.types.ObjectId;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class EntitlementCodec implements CollectibleCodec<Entitlement> {

    private final Codec<Document> documentCodec;

    public EntitlementCodec() {
        this.documentCodec = MongoClientSettings.getDefaultCodecRegistry().get(Document.class);
    }

    @Override
    public Entitlement generateIdIfAbsentFromDocument(Entitlement entitlement) {
        if (!documentHasId(entitlement)) {
            entitlement.setId(new ObjectId().toString());
        }
        return entitlement;
    }

    @Override
    public boolean documentHasId(Entitlement entitlement) {
        return entitlement.getId() != null;
    }

    @Override
    public BsonValue getDocumentId(Entitlement entitlement) {
        return new BsonString(entitlement.getId());
    }

    @Override
    public Entitlement decode(BsonReader bsonReader, DecoderContext decoderContext) {
        var document = documentCodec.decode(bsonReader, decoderContext);
        var entitlement = new Entitlement();
        entitlement.setId(document.getString("_id"));
        entitlement.setName(document.getString("name"));
        var date = (Date) document.get("registered_on");
        LocalDateTime localDateTime;
        if(Objects.isNull(date)){
            localDateTime = null;
        } else {

            localDateTime = date.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        }
        entitlement.setRegisteredOn(localDateTime);

        var attributesDoc = (Document) document.get("attributes");
        if (attributesDoc != null) {
            Map<String, List<String>> attributes = new HashMap<>();
            for (String key : attributesDoc.keySet()) {
                @SuppressWarnings("unchecked")
                List<String> values = (List<String>) attributesDoc.get(key);
                attributes.put(key, values);
            }
            entitlement.setAttributes(attributes);
        }

        return entitlement;
    }

    @Override
    public void encode(BsonWriter bsonWriter, Entitlement entitlement, EncoderContext encoderContext) {

        var doc = new Document();
        doc.put("_id", entitlement.getId());
        doc.put("name", entitlement.getName());
        doc.put("registered_on", entitlement.getRegisteredOn());
        doc.put("attributes", entitlement.getAttributes());

        documentCodec.encode(bsonWriter, doc, encoderContext);
    }

    @Override
    public Class<Entitlement> getEncoderClass() {
        return Entitlement.class;
    }
}
