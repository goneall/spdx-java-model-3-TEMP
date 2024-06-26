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
 
package org.spdx.library.model.v3.software;

import javax.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.spdx.core.DefaultModelStore;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.IModelCopyManager;
import org.spdx.core.IndividualUriValue;
import org.spdx.library.model.v3.ModelObjectV3;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.IModelStore.IModelStoreLock;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

import org.spdx.library.model.v3.SpdxConstantsV3;
import org.spdx.library.model.v3.core.Artifact;
import org.spdx.library.model.v3.core.ProfileIdentifierType;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * A software artifact is a distinct article or unit related to software such as a package, 
 * a file, or a snippet. 
 */
public class SoftwareArtifact extends Artifact  {

	Collection<String> attributionTexts;
	Collection<SoftwarePurpose> additionalPurposes;
	
	/**
	 * Create the SoftwareArtifact with default model store and generated anonymous ID
	 * @throws InvalidSPDXAnalysisException when unable to create the SoftwareArtifact
	 */
	public SoftwareArtifact() throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore().getNextId(IdType.Anonymous));
	}

	/**
	 * @param objectUri URI or anonymous ID for the SoftwareArtifact
	 * @throws InvalidSPDXAnalysisException when unable to create the SoftwareArtifact
	 */
	public SoftwareArtifact(String objectUri) throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore(), objectUri, DefaultModelStore.getDefaultCopyManager(), true);
	}

	/**
	 * @param modelStore Model store where the SoftwareArtifact is to be stored
	 * @param objectUri URI or anonymous ID for the SoftwareArtifact
	 * @param copyManager Copy manager for the SoftwareArtifact - can be null if copying is not required
	 * @param create true if SoftwareArtifact is to be created
	 * @throws InvalidSPDXAnalysisException when unable to create the SoftwareArtifact
	 */
	 @SuppressWarnings("unchecked")
	public SoftwareArtifact(IModelStore modelStore, String objectUri, @Nullable IModelCopyManager copyManager,
			boolean create)	throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create);
		additionalPurposes = (Collection<SoftwarePurpose>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.SOFTWARE_PROP_ADDITIONAL_PURPOSE, SoftwarePurpose.class);
		attributionTexts = (Collection<String>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.SOFTWARE_PROP_ATTRIBUTION_TEXT, String.class);
	}

	/**
	 * Create the SoftwareArtifact from the builder - used in the builder class
	 * @param builder Builder to create the SoftwareArtifact from
	 * @throws InvalidSPDXAnalysisException when unable to create the SoftwareArtifact
	 */
	 @SuppressWarnings("unchecked")
	protected SoftwareArtifact(SoftwareArtifactBuilder builder) throws InvalidSPDXAnalysisException {
		super(builder);
		additionalPurposes = (Collection<SoftwarePurpose>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.SOFTWARE_PROP_ADDITIONAL_PURPOSE, SoftwarePurpose.class);
		attributionTexts = (Collection<String>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.SOFTWARE_PROP_ATTRIBUTION_TEXT, String.class);
		getAdditionalPurposes().addAll(builder.additionalPurposes);
		getAttributionTexts().addAll(builder.attributionTexts);
		setPrimaryPurpose(builder.primaryPurpose);
		setContentIdentifier(builder.contentIdentifier);
		setCopyrightText(builder.copyrightText);
	}

	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#getType()
	 */
	@Override
	public String getType() {
		return "Software.SoftwareArtifact";
	}
	
	// Getters and Setters
	public Collection<SoftwarePurpose> getAdditionalPurposes() {
		return additionalPurposes;
	}
	public Collection<String> getAttributionTexts() {
		return attributionTexts;
	}
	
	
	/**
	 * @return the primaryPurpose
	 */
	 @SuppressWarnings("unchecked")
	public Optional<SoftwarePurpose> getPrimaryPurpose() throws InvalidSPDXAnalysisException {
		Optional<Enum<?>> retval = getEnumPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_PRIMARY_PURPOSE);
		if (retval.isPresent()) {
			if (!(retval.get() instanceof SoftwarePurpose)) {
				throw new InvalidSPDXAnalysisException("Incorrect type stored for ");
			}
			return (Optional<SoftwarePurpose>)(Optional<?>)(retval);
		} else {
			return Optional.empty();
		}
	}
	/**
	 * @param primaryPurpose the primaryPurpose to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public SoftwareArtifact setPrimaryPurpose(@Nullable SoftwarePurpose primaryPurpose) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_PRIMARY_PURPOSE, primaryPurpose);
		return this;
	}

		/**
	 * @return the contentIdentifier
	 */
	public Optional<String> getContentIdentifier() throws InvalidSPDXAnalysisException {
		return getStringPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_CONTENT_IDENTIFIER);
	}
	/**
	 * @param contentIdentifier the contentIdentifier to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public SoftwareArtifact setContentIdentifier(@Nullable String contentIdentifier) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_CONTENT_IDENTIFIER, contentIdentifier);
		return this;
	}

		/**
	 * @return the copyrightText
	 */
	public Optional<String> getCopyrightText() throws InvalidSPDXAnalysisException {
		return getStringPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_COPYRIGHT_TEXT);
	}
	/**
	 * @param copyrightText the copyrightText to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public SoftwareArtifact setCopyrightText(@Nullable String copyrightText) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_COPYRIGHT_TEXT, copyrightText);
		return this;
	}
	
	
	@Override
	public String toString() {
		return "SoftwareArtifact: "+getObjectUri();
	}
	
	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#_verify(java.util.List)
	 */
	@Override
	public List<String> _verify(Set<String> verifiedIds, String specVersionForVerify, List<IndividualUriValue> profiles) {
		List<String> retval = new ArrayList<>();
		retval.addAll(super._verify(verifiedIds, specVersionForVerify, profiles));
		try {
			@SuppressWarnings("unused")
			Optional<SoftwarePurpose> primaryPurpose = getPrimaryPurpose();
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting primaryPurpose for SoftwareArtifact: "+e.getMessage());
		}
		try {
			@SuppressWarnings("unused")
			Optional<String> contentIdentifier = getContentIdentifier();
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting contentIdentifier for SoftwareArtifact: "+e.getMessage());
		}
		try {
			@SuppressWarnings("unused")
			Optional<String> copyrightText = getCopyrightText();
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting copyrightText for SoftwareArtifact: "+e.getMessage());
		}
		return retval;
	}
	
	public static class SoftwareArtifactBuilder extends ArtifactBuilder {
	
		/**
		 * Create an SoftwareArtifactBuilder from another model object copying the modelStore and copyManager and using an anonymous ID
		 * @param from model object to copy the model store and copyManager from
		 * @throws InvalidSPDXAnalysisException
		 */
		public SoftwareArtifactBuilder(ModelObjectV3 from) throws InvalidSPDXAnalysisException {
			this(from, from.getModelStore().getNextId(IdType.Anonymous));
		}
	
		/**
		 * Create an SoftwareArtifactBuilder from another model object copying the modelStore and copyManager
		 * @param from model object to copy the model store and copyManager from
		 * @param objectUri URI for the object
		 * @param objectUri
		 */
		public SoftwareArtifactBuilder(ModelObjectV3 from, String objectUri) {
			this(from.getModelStore(), objectUri, from.getCopyManager());
			setStrict(from.isStrict());
		}
		
		/**
		 * Creates a SoftwareArtifactBuilder
		 * @param modelStore model store for the built SoftwareArtifact
		 * @param objectUri objectUri for the built SoftwareArtifact
		 * @param copyManager optional copyManager for the built SoftwareArtifact
		 */
		public SoftwareArtifactBuilder(IModelStore modelStore, String objectUri, @Nullable IModelCopyManager copyManager) {
			super(modelStore, objectUri, copyManager);
		}
		
		Collection<SoftwarePurpose> additionalPurposes = new ArrayList<>();
		Collection<String> attributionTexts = new ArrayList<>();
		SoftwarePurpose primaryPurpose = null;
		String contentIdentifier = null;
		String copyrightText = null;
		
		
		/**
		 * Adds a additionalPurpose to the initial collection
		 * @parameter additionalPurpose additionalPurpose to add
		 * @return this for chaining
		**/
		public SoftwareArtifactBuilder addAdditionalPurpose(SoftwarePurpose additionalPurpose) {
			if (Objects.nonNull(additionalPurpose)) {
				additionalPurposes.add(additionalPurpose);
			}
			return this;
		}
		
		/**
		 * Adds all elements from a collection to the initial additionalPurpose collection
		 * @parameter additionalPurposeCollection collection to initialize the additionalPurpose
		 * @return this for chaining
		**/
		public SoftwareArtifactBuilder addAllAdditionalPurpose(Collection<SoftwarePurpose> additionalPurposeCollection) {
			if (Objects.nonNull(additionalPurposeCollection)) {
				additionalPurposes.addAll(additionalPurposeCollection);
			}
			return this;
		}
		
		/**
		 * Adds a attributionText to the initial collection
		 * @parameter attributionText attributionText to add
		 * @return this for chaining
		**/
		public SoftwareArtifactBuilder addAttributionText(String attributionText) {
			if (Objects.nonNull(attributionText)) {
				attributionTexts.add(attributionText);
			}
			return this;
		}
		
		/**
		 * Adds all elements from a collection to the initial attributionText collection
		 * @parameter attributionTextCollection collection to initialize the attributionText
		 * @return this for chaining
		**/
		public SoftwareArtifactBuilder addAllAttributionText(Collection<String> attributionTextCollection) {
			if (Objects.nonNull(attributionTextCollection)) {
				attributionTexts.addAll(attributionTextCollection);
			}
			return this;
		}
		
		/**
		 * Sets the initial value of primaryPurpose
		 * @parameter primaryPurpose value to set
		 * @return this for chaining
		**/
		public SoftwareArtifactBuilder setPrimaryPurpose(SoftwarePurpose primaryPurpose) {
			this.primaryPurpose = primaryPurpose;
			return this;
		}
		
		/**
		 * Sets the initial value of contentIdentifier
		 * @parameter contentIdentifier value to set
		 * @return this for chaining
		**/
		public SoftwareArtifactBuilder setContentIdentifier(String contentIdentifier) {
			this.contentIdentifier = contentIdentifier;
			return this;
		}
		
		/**
		 * Sets the initial value of copyrightText
		 * @parameter copyrightText value to set
		 * @return this for chaining
		**/
		public SoftwareArtifactBuilder setCopyrightText(String copyrightText) {
			this.copyrightText = copyrightText;
			return this;
		}
	
		
		/**
		 * @return the SoftwareArtifact
		 * @throws InvalidSPDXAnalysisException on any errors during build
		 */
		public SoftwareArtifact build() throws InvalidSPDXAnalysisException {
			IModelStoreLock lock = modelStore.enterCriticalSection(false);
			try {
				return new SoftwareArtifact(this);
			} finally {
				modelStore.leaveCriticalSection(lock);
			}
		}
	}
}
