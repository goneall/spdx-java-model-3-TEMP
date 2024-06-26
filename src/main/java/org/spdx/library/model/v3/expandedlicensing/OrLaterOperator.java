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
 
package org.spdx.library.model.v3.expandedlicensing;

import javax.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.spdx.library.DefaultModelStore;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.model.ModelObject;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.IModelStore.IModelStoreLock;

import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

import org.spdx.library.model.v3.SpdxConstantsV3;
import org.spdx.library.model.v3.core.ProfileIdentifierType;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * An OrLaterOperator indicates that this portion of the AnyLicenseInfo represents 
 * either (1) the specified version of the corresponding License, or (2) any later version 
 * of that License. It is represented in the SPDX License Expression Syntax by the `+` 
 * operator. It is context-dependent, and unspecified by SPDX, as to what constitutes 
 * a "later version" of any particular License. Some Licenses may not be versioned, 
 * or may not have clearly-defined ordering for versions. The consumer of SPDX data 
 * will need to determine for themselves what meaning to attribute to a "later version" 
 * operator for a particular License. 
 */
public class OrLaterOperator extends ExtendableLicense  {

	
	/**
	 * Create the OrLaterOperator with default model store and generated anonymous ID
	 * @throws InvalidSPDXAnalysisException when unable to create the OrLaterOperator
	 */
	public OrLaterOperator() throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore().getNextId(IdType.Anonymous, null));
	}

	/**
	 * @param objectUri URI or anonymous ID for the OrLaterOperator
	 * @throws InvalidSPDXAnalysisException when unable to create the OrLaterOperator
	 */
	public OrLaterOperator(String objectUri) throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore(), objectUri, DefaultModelStore.getDefaultCopyManager(), true);
	}

	/**
	 * @param modelStore Model store where the OrLaterOperator is to be stored
	 * @param objectUri URI or anonymous ID for the OrLaterOperator
	 * @param copyManager Copy manager for the OrLaterOperator - can be null if copying is not required
	 * @param create true if OrLaterOperator is to be created
	 * @throws InvalidSPDXAnalysisException when unable to create the OrLaterOperator
	 */
	public OrLaterOperator(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager,
			boolean create)	throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create);
	}

	/**
	 * Create the OrLaterOperator from the builder - used in the builder class
	 * @param builder Builder to create the OrLaterOperator from
	 * @throws InvalidSPDXAnalysisException when unable to create the OrLaterOperator
	 */
	protected OrLaterOperator(OrLaterOperatorBuilder builder) throws InvalidSPDXAnalysisException {
		super(builder);
		setSubjectLicense(builder.subjectLicense);
	}

	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#getType()
	 */
	@Override
	public String getType() {
		return "ExpandedLicensing.OrLaterOperator";
	}
	
	// Getters and Setters
	

	/**
	 * @return the subjectLicense
	 */
	 @SuppressWarnings("unchecked")
	public @Nullable License getSubjectLicense() throws InvalidSPDXAnalysisException {
		Optional<Object> retval = getObjectPropertyValue(SpdxConstantsV3.EXPANDED_LICENSING_PROP_SUBJECT_LICENSE);
		if (retval.isPresent()) {
			if (!(retval.get() instanceof License)) {
				throw new InvalidSPDXAnalysisException("Incorrect type stored for ");
			}
			return (License)(retval.get());
		} else {
			return null;
		}
	}
		
	/**
	 * @param subjectLicense the subjectLicense to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public OrLaterOperator setSubjectLicense(@Nullable License subjectLicense) throws InvalidSPDXAnalysisException {
		if (isStrict() && Objects.isNull(subjectLicense)) {
			throw new InvalidSPDXAnalysisException("subjectLicense is a required property");
		}
		setPropertyValue(SpdxConstantsV3.EXPANDED_LICENSING_PROP_SUBJECT_LICENSE, subjectLicense);
		return this;
	}
	
	
	@Override
	public String toString() {
		return "OrLaterOperator: "+getObjectUri();
	}
	
	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#_verify(java.util.List)
	 */
	@Override
	public List<String> _verify(Set<String> verifiedIds, String specVersionForVerify, List<ProfileIdentifierType> profiles) {
		List<String> retval = new ArrayList<>();
		retval.addAll(super._verify(verifiedIds, specVersionForVerify, profiles));
		License subjectLicense;
		try {
			subjectLicense = getSubjectLicense();
			if (Objects.nonNull(subjectLicense)) {
				retval.addAll(subjectLicense.verify(verifiedIds, specVersionForVerify, profiles));
			} else if (!Collections.disjoint(profiles, Arrays.asList(new ProfileIdentifierType[] { ProfileIdentifierType.EXPANDED_LICENSING }))) {
					retval.add("Missing subjectLicense in OrLaterOperator");
			}
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting subjectLicense for OrLaterOperator: "+e.getMessage());
		}
		return retval;
	}
	
	public static class OrLaterOperatorBuilder extends ExtendableLicenseBuilder {
	
		/**
		 * Create an OrLaterOperatorBuilder from another model object copying the modelStore and copyManager and using an anonymous ID
		 * @param from model object to copy the model store and copyManager from
		 * @throws InvalidSPDXAnalysisException
		 */
		public OrLaterOperatorBuilder(ModelObject from) throws InvalidSPDXAnalysisException {
			this(from, from.getModelStore().getNextId(IdType.Anonymous, null));
		}
	
		/**
		 * Create an OrLaterOperatorBuilder from another model object copying the modelStore and copyManager
		 * @param from model object to copy the model store and copyManager from
		 * @param objectUri URI for the object
		 * @param objectUri
		 */
		public OrLaterOperatorBuilder(ModelObject from, String objectUri) {
			this(from.getModelStore(), objectUri, from.getCopyManager());
			setStrict(from.isStrict());
		}
		
		/**
		 * Creates a OrLaterOperatorBuilder
		 * @param modelStore model store for the built OrLaterOperator
		 * @param objectUri objectUri for the built OrLaterOperator
		 * @param copyManager optional copyManager for the built OrLaterOperator
		 */
		public OrLaterOperatorBuilder(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager) {
			super(modelStore, objectUri, copyManager);
		}
		
		License subjectLicense = null;
		
		
		/**
		 * Sets the initial value of subjectLicense
		 * @parameter subjectLicense value to set
		 * @return this for chaining
		**/
		public OrLaterOperatorBuilder setSubjectLicense(License subjectLicense) {
			this.subjectLicense = subjectLicense;
			return this;
		}
	
		
		/**
		 * @return the OrLaterOperator
		 * @throws InvalidSPDXAnalysisException on any errors during build
		 */
		public OrLaterOperator build() throws InvalidSPDXAnalysisException {
			IModelStoreLock lock = modelStore.enterCriticalSection(false);
			try {
				return new OrLaterOperator(this);
			} finally {
				modelStore.leaveCriticalSection(lock);
			}
		}
	}
}
