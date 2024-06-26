/**
 * Copyright (c) 2024 Source Auditor Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
 
package org.spdx.library.model.v3.core;

import javax.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.spdx.core.DefaultModelStore;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.IModelCopyManager;
import org.spdx.core.IndividualUriValue;
import org.spdx.library.model.v3.ModelObjectV3;
import org.spdx.library.model.v3.SpdxConstantsV3;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.IModelStore.IModelStoreLock;

import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * The class used for implementing a generic string mapping (also known as associative 
 * array, dictionary, or hash map) in SPDX. Each DictionaryEntry contains a key-value 
 * pair which maps the key to its associated value. To implement a dictionary, this class 
 * is to be used in a collection with unique keys. 
 */
public class DictionaryEntry extends ModelObjectV3  {

	
	/**
	 * Create the DictionaryEntry with default model store and generated anonymous ID
	 * @throws InvalidSPDXAnalysisException when unable to create the DictionaryEntry
	 */
	public DictionaryEntry() throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore().getNextId(IdType.Anonymous));
	}

	/**
	 * @param objectUri URI or anonymous ID for the DictionaryEntry
	 * @throws InvalidSPDXAnalysisException when unable to create the DictionaryEntry
	 */
	public DictionaryEntry(String objectUri) throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore(), objectUri, DefaultModelStore.getDefaultCopyManager(), true);
	}

	/**
	 * @param modelStore Model store where the DictionaryEntry is to be stored
	 * @param objectUri URI or anonymous ID for the DictionaryEntry
	 * @param copyManager Copy manager for the DictionaryEntry - can be null if copying is not required
	 * @param create true if DictionaryEntry is to be created
	 * @throws InvalidSPDXAnalysisException when unable to create the DictionaryEntry
	 */
	public DictionaryEntry(IModelStore modelStore, String objectUri, @Nullable IModelCopyManager copyManager,
			boolean create)	throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create);
	}

	/**
	 * Create the DictionaryEntry from the builder - used in the builder class
	 * @param builder Builder to create the DictionaryEntry from
	 * @throws InvalidSPDXAnalysisException when unable to create the DictionaryEntry
	 */
	protected DictionaryEntry(DictionaryEntryBuilder builder) throws InvalidSPDXAnalysisException {
		super(builder);
		setValue(builder.value);
		setKey(builder.key);
	}

	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#getType()
	 */
	@Override
	public String getType() {
		return "Core.DictionaryEntry";
	}
	
	// Getters and Setters
	

		/**
	 * @return the value
	 */
	public Optional<String> getValue() throws InvalidSPDXAnalysisException {
		return getStringPropertyValue(SpdxConstantsV3.CORE_PROP_VALUE);
	}
	/**
	 * @param value the value to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public DictionaryEntry setValue(@Nullable String value) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.CORE_PROP_VALUE, value);
		return this;
	}

	/**
	 * @return the key
	 */
	public @Nullable String getKey() throws InvalidSPDXAnalysisException {
		Optional<String> retval = getStringPropertyValue(SpdxConstantsV3.CORE_PROP_KEY);
		return retval.isPresent() ? retval.get() : null;
	}
		/**
	 * @param key the key to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public DictionaryEntry setKey(@Nullable String key) throws InvalidSPDXAnalysisException {
		if (isStrict() && Objects.isNull(key)) {
			throw new InvalidSPDXAnalysisException("key is a required property");
		}
		setPropertyValue(SpdxConstantsV3.CORE_PROP_KEY, key);
		return this;
	}
	
	
	@Override
	public String toString() {
		return "DictionaryEntry: "+getObjectUri();
	}
	
	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#_verify(java.util.List)
	 */
	@Override
	public List<String> _verify(Set<String> verifiedIds, String specVersionForVerify, List<IndividualUriValue> profiles) {
		List<String> retval = new ArrayList<>();
		try {
			@SuppressWarnings("unused")
			Optional<String> value = getValue();
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting value for DictionaryEntry: "+e.getMessage());
		}
		try {
			String key = getKey();
			if (Objects.isNull(key) &&
					Collections.disjoint(profiles, Arrays.asList(new ProfileIdentifierType[] { ProfileIdentifierType.CORE }))) {
				retval.add("Missing key in DictionaryEntry");
			}
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting key for DictionaryEntry: "+e.getMessage());
		}
		return retval;
	}
	
	public static class DictionaryEntryBuilder extends CoreModelObjectBuilder {
	
		/**
		 * Create an DictionaryEntryBuilder from another model object copying the modelStore and copyManager and using an anonymous ID
		 * @param from model object to copy the model store and copyManager from
		 * @throws InvalidSPDXAnalysisException
		 */
		public DictionaryEntryBuilder(ModelObjectV3 from) throws InvalidSPDXAnalysisException {
			this(from, from.getModelStore().getNextId(IdType.Anonymous));
		}
	
		/**
		 * Create an DictionaryEntryBuilder from another model object copying the modelStore and copyManager
		 * @param from model object to copy the model store and copyManager from
		 * @param objectUri URI for the object
		 * @param objectUri
		 */
		public DictionaryEntryBuilder(ModelObjectV3 from, String objectUri) {
			this(from.getModelStore(), objectUri, from.getCopyManager());
			setStrict(from.isStrict());
		}
		
		/**
		 * Creates a DictionaryEntryBuilder
		 * @param modelStore model store for the built DictionaryEntry
		 * @param objectUri objectUri for the built DictionaryEntry
		 * @param copyManager optional copyManager for the built DictionaryEntry
		 */
		public DictionaryEntryBuilder(IModelStore modelStore, String objectUri, @Nullable IModelCopyManager copyManager) {
			super(modelStore, objectUri, copyManager);
		}
		
		String value = null;
		String key = null;
		
		
		/**
		 * Sets the initial value of value
		 * @parameter value value to set
		 * @return this for chaining
		**/
		public DictionaryEntryBuilder setValue(String value) {
			this.value = value;
			return this;
		}
		
		/**
		 * Sets the initial value of key
		 * @parameter key value to set
		 * @return this for chaining
		**/
		public DictionaryEntryBuilder setKey(String key) {
			this.key = key;
			return this;
		}
	
		
		/**
		 * @return the DictionaryEntry
		 * @throws InvalidSPDXAnalysisException on any errors during build
		 */
		public DictionaryEntry build() throws InvalidSPDXAnalysisException {
			IModelStoreLock lock = modelStore.enterCriticalSection(false);
			try {
				return new DictionaryEntry(this);
			} finally {
				modelStore.leaveCriticalSection(lock);
			}
		}
	}
}
