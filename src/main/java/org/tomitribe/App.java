/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.tomitribe;

import org.tomitribe.crest.api.Command;
import org.tomitribe.crest.api.Default;
import org.tomitribe.crest.api.Option;
import org.tomitribe.crest.api.Required;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class App {

    @Command
    public void addEntry (
            final @Option("keystore") @Required File keyStore,
            final @Option("storetype") @Default("jks") String storeType,
            final @Option("storepass") @Required String keystorePass,
            final @Option("alias") @Required String keyAlias,
            final @Option("keypass") @Required String keyPass,
            final @Option("privatekey") @Required @IsFile File privateKey,
            final @Option("certificate") File[] certificates) throws Exception {

        try {
            final KeyStore ks = KeyStore.getInstance(storeType);

            if (! keyStore.exists()) {
                ks.load(null, keystorePass.toCharArray());
            } else {
                ks.load(new FileInputStream(keyStore), keyPass.toCharArray());
            }


            final Key key = ks.getKey(keyAlias, keyPass.toCharArray());
            if (key != null) {
                throw new RuntimeException("Entry with alias " + keyAlias + " already exists in the keystore");
            }

            final PrivateKey pk = PEM.readPrivateKey(new FileInputStream(privateKey));
            final List<Certificate> chain = new ArrayList<Certificate>();

            for (final File certFile : certificates) {
                if (certFile.exists() && certFile.isFile()) {
                    chain.addAll(Arrays.asList(PEM.readCertificates(new FileInputStream(certFile))));
                }
            }

            ks.setKeyEntry(keyAlias, pk, keyPass.toCharArray(), chain.toArray(new Certificate[0]));
            ks.store(new FileOutputStream(keyStore), keystorePass.toCharArray());
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}
