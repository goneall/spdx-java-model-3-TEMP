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

import java.util.Optional;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * An IntegrityMethod provides an independently reproducible mechanism that permits 
 * verification of a specific Element that correlates to the data in this SPDX document. 
 * This identifier enables a recipient to determine if anything in the original Element 
 * has been changed and eliminates confusion over which version or modification of 
 * a specific Element is referenced. 
 */
public class IntegrityMethod extends ModelObjectV3  {

	
	/**
	 * Create the IntegrityMethod with default model store and generated anonymous ID
	 * @throws InvalidSPDXAnalysisException when unable to create the IntegrityMethod
	 */
	public IntegrityMethod() throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore().getNextId(IdType.Anonymous));
	}

	/**
	 * @param objectUri URI or anonymous ID for the IntegrityMethod
	 * @throws InvalidSPDXAnalysisException when unable to create the IntegrityMethod
	 */
	public IntegrityMethod(String objectUri) throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore(), objectUri, DefaultModelStore.getDefaultCopyManager(), true);
	}

	/**
	 * @param modelStore Model store where the IntegrityMethod is to be stored
	 * @param objectUri URI or anonymous ID for the IntegrityMethod
	 * @param copyManager Copy manager for the IntegrityMethod - can be null if copying is not required
	 * @param create true if IntegrityMethod is to be created
	 * @throws InvalidSPDXAnalysisException when unable to create the IntegrityMethod
	 */
	public IntegrityMethod(IModelStore modelStore, String objectUri, @Nullable IModelCopyManager copyManager,
			boolean create)	throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create);
	}

	/**
	 * Create the IntegrityMethod from the builder - used in the builder class
	 * @param builder Builder to create the IntegrityMethod from
	 * @throws InvalidSPDXAnalysisException when unable to create the IntegrityMethod
	 */
	protected IntegrityMethod(IntegrityMethodBuilder builder) throws InvalidSPDXAnalysisException {
		super(builder);
		setComment(builder.comment);
	}

	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#getType()
	 */
	@Override
	public String getType() {
		return "Core.IntegrityMethod";
	}
	
	// Getters and Setters
	

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
	public IntegrityMethod setComment(@Nullable String comment) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.CORE_PROP_COMMENT, comment);
		return this;
	}
	
	
	@Override
	public String toString() {
		return "IntegrityMethod: "+getObjectUri();
	}
	
	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#_verify(java.util.List)
	 */
	@Override
	public List<String> _verify(Set<String> verifiedIds, String specVersionForVerify, List<IndividualUriValue> profiles) {
		List<String> retval = new ArrayList<>();
		try {
			@SuppressWarnings("unused")
			Optional<String> comment = getComment();
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting comment for IntegrityMethod: "+e.getMessage());
		}
		return retval;
	}
	
	public static class IntegrityMethodBuilder extends CoreModelObjectBuilder {
	
		/**
		 * Create an IntegrityMethodBuilder from another model object copying the modelStore and copyManager and using an anonymous ID
		 * @param from model object to copy the model store and copyManager from
		 * @throws InvalidSPDXAnalysisException
		 */
		public IntegrityMethodBuilder(ModelObjectV3 from) throws InvalidSPDXAnalysisException {
			this(from, from.getModelStore().getNextId(IdType.Anonymous));
		}
	
		/**
		 * Create an IntegrityMethodBuilder from another model object copying the modelStore and copyManager
		 * @param from model object to copy the model store and copyManager from
		 * @param objectUri URI for the object
		 * @param objectUri
		 */
		public IntegrityMethodBuilder(ModelObjectV3 from, String objectUri) {
			this(from.getModelStore(), objectUri, from.getCopyManager());
			setStrict(from.isStrict());
		}
		
		/**
		 * Creates a IntegrityMethodBuilder
		 * @param modelStore model store for the built IntegrityMethod
		 * @param objectUri objectUri for the built IntegrityMethod
		 * @param copyManager optional copyManager for the built IntegrityMethod
		 */
		public IntegrityMethodBuilder(IModelStore modelStore, String objectUri, @Nullable IModelCopyManager copyManager) {
			super(modelStore, objectUri, copyManager);
		}
		
		String comment = null;
		
		
		/**
		 * Sets the initial value of comment
		 * @parameter comment value to set
		 * @return this for chaining
		**/
		public IntegrityMethodBuilder setComment(String comment) {
			this.comment = comment;
			return this;
		}
	
		
		/**
		 * @return the IntegrityMethod
		 * @throws InvalidSPDXAnalysisException on any errors during build
		 */
		public IntegrityMethod build() throws InvalidSPDXAnalysisException {
			IModelStoreLock lock = modelStore.enterCriticalSection(false);
			try {
				return new IntegrityMethod(this);
			} finally {
				modelStore.leaveCriticalSection(lock);
			}
		}
	}
}
