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

import org.spdx.core.CoreModelObject;
import org.spdx.core.DefaultModelStore;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.IModelCopyManager;
import org.spdx.core.IndividualUriValue;
import org.spdx.library.model.v3.ModelObjectV3;
import org.spdx.library.model.v3.SpdxConstantsV3;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.IModelStore.IModelStoreLock;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * An External Reference points to a resource outside the scope of the SPDX-3.0 content 
 * that provides additional characteristics of an Element. 
 */
public class ExternalRef extends ModelObjectV3  {

	Collection<String> locators;
	
	/**
	 * Create the ExternalRef with default model store and generated anonymous ID
	 * @throws InvalidSPDXAnalysisException when unable to create the ExternalRef
	 */
	public ExternalRef() throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore().getNextId(IdType.Anonymous));
	}

	/**
	 * @param objectUri URI or anonymous ID for the ExternalRef
	 * @throws InvalidSPDXAnalysisException when unable to create the ExternalRef
	 */
	public ExternalRef(String objectUri) throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore(), objectUri, DefaultModelStore.getDefaultCopyManager(), true);
	}

	/**
	 * @param modelStore Model store where the ExternalRef is to be stored
	 * @param objectUri URI or anonymous ID for the ExternalRef
	 * @param copyManager Copy manager for the ExternalRef - can be null if copying is not required
	 * @param create true if ExternalRef is to be created
	 * @throws InvalidSPDXAnalysisException when unable to create the ExternalRef
	 */
	 @SuppressWarnings("unchecked")
	public ExternalRef(IModelStore modelStore, String objectUri, @Nullable IModelCopyManager copyManager,
			boolean create)	throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create);
		locators = (Collection<String>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.CORE_PROP_LOCATOR, String.class);
	}

	/**
	 * Create the ExternalRef from the builder - used in the builder class
	 * @param builder Builder to create the ExternalRef from
	 * @throws InvalidSPDXAnalysisException when unable to create the ExternalRef
	 */
	 @SuppressWarnings("unchecked")
	protected ExternalRef(ExternalRefBuilder builder) throws InvalidSPDXAnalysisException {
		super(builder);
		locators = (Collection<String>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.CORE_PROP_LOCATOR, String.class);
		getLocators().addAll(builder.locators);
		setExternalRefType(builder.externalRefType);
		setComment(builder.comment);
		setContentType(builder.contentType);
	}

	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#getType()
	 */
	@Override
	public String getType() {
		return "Core.ExternalRef";
	}
	
	// Getters and Setters
	public Collection<String> getLocators() {
		return locators;
	}
	
	
	/**
	 * @return the externalRefType
	 */
	 @SuppressWarnings("unchecked")
	public Optional<ExternalRefType> getExternalRefType() throws InvalidSPDXAnalysisException {
		Optional<Enum<?>> retval = getEnumPropertyValue(SpdxConstantsV3.CORE_PROP_EXTERNAL_REF_TYPE);
		if (retval.isPresent()) {
			if (!(retval.get() instanceof ExternalRefType)) {
				throw new InvalidSPDXAnalysisException("Incorrect type stored for ");
			}
			return (Optional<ExternalRefType>)(Optional<?>)(retval);
		} else {
			return Optional.empty();
		}
	}
	/**
	 * @param externalRefType the externalRefType to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public ExternalRef setExternalRefType(@Nullable ExternalRefType externalRefType) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.CORE_PROP_EXTERNAL_REF_TYPE, externalRefType);
		return this;
	}

		/**
	 * @return the comment
	 */
	public Optional<String> getComment() throws InvalidSPDXAnalysisException {
		return getStringPropertyValue(SpdxConstantsV3.CORE_PROP_COMMENT);
	}
	/**
	 * @param comment the comment to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public ExternalRef setComment(@Nullable String comment) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.CORE_PROP_COMMENT, comment);
		return this;
	}

		/**
	 * @return the contentType
	 */
	public Optional<String> getContentType() throws InvalidSPDXAnalysisException {
		return getStringPropertyValue(SpdxConstantsV3.CORE_PROP_CONTENT_TYPE);
	}
	/**
	 * @param contentType the contentType to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public ExternalRef setContentType(@Nullable String contentType) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.CORE_PROP_CONTENT_TYPE, contentType);
		return this;
	}
	
	
	@Override
	public String toString() {
		return "ExternalRef: "+getObjectUri();
	}
	
	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#_verify(java.util.List)
	 */
	@Override
	public List<String> _verify(Set<String> verifiedIds, String specVersionForVerify, List<IndividualUriValue> profiles) {
		List<String> retval = new ArrayList<>();
		try {
			@SuppressWarnings("unused")
			Optional<ExternalRefType> externalRefType = getExternalRefType();
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting externalRefType for ExternalRef: "+e.getMessage());
		}
		try {
			@SuppressWarnings("unused")
			Optional<String> comment = getComment();
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting comment for ExternalRef: "+e.getMessage());
		}
		try {
			@SuppressWarnings("unused")
			Optional<String> contentType = getContentType();
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting contentType for ExternalRef: "+e.getMessage());
		}
		return retval;
	}
	
	public static class ExternalRefBuilder extends CoreModelObjectBuilder {
	
		/**
		 * Create an ExternalRefBuilder from another model object copying the modelStore and copyManager and using an anonymous ID
		 * @param from model object to copy the model store and copyManager from
		 * @throws InvalidSPDXAnalysisException
		 */
		public ExternalRefBuilder(CoreModelObject from) throws InvalidSPDXAnalysisException {
			this(from, from.getModelStore().getNextId(IdType.Anonymous));
		}
	
		/**
		 * Create an ExternalRefBuilder from another model object copying the modelStore and copyManager
		 * @param from model object to copy the model store and copyManager from
		 * @param objectUri URI for the object
		 * @param objectUri
		 */
		public ExternalRefBuilder(CoreModelObject from, String objectUri) {
			this(from.getModelStore(), objectUri, from.getCopyManager());
			setStrict(from.isStrict());
		}
		
		/**
		 * Creates a ExternalRefBuilder
		 * @param modelStore model store for the built ExternalRef
		 * @param objectUri objectUri for the built ExternalRef
		 * @param copyManager optional copyManager for the built ExternalRef
		 */
		public ExternalRefBuilder(IModelStore modelStore, String objectUri, @Nullable IModelCopyManager copyManager) {
			super(modelStore, objectUri, copyManager);
		}
		
		Collection<String> locators = new ArrayList<>();
		ExternalRefType externalRefType = null;
		String comment = null;
		String contentType = null;
		
		
		/**
		 * Adds a locator to the initial collection
		 * @parameter locator locator to add
		 * @return this for chaining
		**/
		public ExternalRefBuilder addLocator(String locator) {
			if (Objects.nonNull(locator)) {
				locators.add(locator);
			}
			return this;
		}
		
		/**
		 * Adds all elements from a collection to the initial locator collection
		 * @parameter locatorCollection collection to initialize the locator
		 * @return this for chaining
		**/
		public ExternalRefBuilder addAllLocator(Collection<String> locatorCollection) {
			if (Objects.nonNull(locatorCollection)) {
				locators.addAll(locatorCollection);
			}
			return this;
		}
		
		/**
		 * Sets the initial value of externalRefType
		 * @parameter externalRefType value to set
		 * @return this for chaining
		**/
		public ExternalRefBuilder setExternalRefType(ExternalRefType externalRefType) {
			this.externalRefType = externalRefType;
			return this;
		}
		
		/**
		 * Sets the initial value of comment
		 * @parameter comment value to set
		 * @return this for chaining
		**/
		public ExternalRefBuilder setComment(String comment) {
			this.comment = comment;
			return this;
		}
		
		/**
		 * Sets the initial value of contentType
		 * @parameter contentType value to set
		 * @return this for chaining
		**/
		public ExternalRefBuilder setContentType(String contentType) {
			this.contentType = contentType;
			return this;
		}
	
		
		/**
		 * @return the ExternalRef
		 * @throws InvalidSPDXAnalysisException on any errors during build
		 */
		public ExternalRef build() throws InvalidSPDXAnalysisException {
			IModelStoreLock lock = modelStore.enterCriticalSection(false);
			try {
				return new ExternalRef(this);
			} finally {
				modelStore.leaveCriticalSection(lock);
			}
		}
	}
}
