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

import org.spdx.library.DefaultModelStore;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.model.ModelObject;
import org.spdx.library.model.v3.SpdxConstantsV3;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.IModelStore.IModelStoreLock;

import java.util.Optional;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * A bundle is a collection of Elements that have a shared context. 
 */
public class Bundle extends ElementCollection  {

	
	/**
	 * Create the Bundle with default model store and generated anonymous ID
	 * @throws InvalidSPDXAnalysisException when unable to create the Bundle
	 */
	public Bundle() throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore().getNextId(IdType.Anonymous, null));
	}

	/**
	 * @param objectUri URI or anonymous ID for the Bundle
	 * @throws InvalidSPDXAnalysisException when unable to create the Bundle
	 */
	public Bundle(String objectUri) throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore(), objectUri, DefaultModelStore.getDefaultCopyManager(), true);
	}

	/**
	 * @param modelStore Model store where the Bundle is to be stored
	 * @param objectUri URI or anonymous ID for the Bundle
	 * @param copyManager Copy manager for the Bundle - can be null if copying is not required
	 * @param create true if Bundle is to be created
	 * @throws InvalidSPDXAnalysisException when unable to create the Bundle
	 */
	public Bundle(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager,
			boolean create)	throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create);
	}

	/**
	 * Create the Bundle from the builder - used in the builder class
	 * @param builder Builder to create the Bundle from
	 * @throws InvalidSPDXAnalysisException when unable to create the Bundle
	 */
	protected Bundle(BundleBuilder builder) throws InvalidSPDXAnalysisException {
		super(builder);
		setContext(builder.context);
	}

	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#getType()
	 */
	@Override
	public String getType() {
		return "Core.Bundle";
	}
	
	// Getters and Setters
	

		/**
	 * @return the context
	 */
	public Optional<String> getContext() throws InvalidSPDXAnalysisException {
		return getStringPropertyValue(SpdxConstantsV3.CORE_PROP_CONTEXT);
	}
	/**
	 * @param context the context to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public Bundle setContext(@Nullable String context) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.CORE_PROP_CONTEXT, context);
		return this;
	}
	
	
	@Override
	public String toString() {
		return "Bundle: "+getObjectUri();
	}
	
	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#_verify(java.util.List)
	 */
	@Override
	public List<String> _verify(Set<String> verifiedIds, String specVersionForVerify, List<ProfileIdentifierType> profiles) {
		List<String> retval = new ArrayList<>();
		retval.addAll(super._verify(verifiedIds, specVersionForVerify, profiles));
		try {
			@SuppressWarnings("unused")
			Optional<String> context = getContext();
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting context for Bundle: "+e.getMessage());
		}
		return retval;
	}
	
	public static class BundleBuilder extends ElementCollectionBuilder {
	
		/**
		 * Create an BundleBuilder from another model object copying the modelStore and copyManager and using an anonymous ID
		 * @param from model object to copy the model store and copyManager from
		 * @throws InvalidSPDXAnalysisException
		 */
		public BundleBuilder(ModelObject from) throws InvalidSPDXAnalysisException {
			this(from, from.getModelStore().getNextId(IdType.Anonymous, null));
		}
	
		/**
		 * Create an BundleBuilder from another model object copying the modelStore and copyManager
		 * @param from model object to copy the model store and copyManager from
		 * @param objectUri URI for the object
		 * @param objectUri
		 */
		public BundleBuilder(ModelObject from, String objectUri) {
			this(from.getModelStore(), objectUri, from.getCopyManager());
			setStrict(from.isStrict());
		}
		
		/**
		 * Creates a BundleBuilder
		 * @param modelStore model store for the built Bundle
		 * @param objectUri objectUri for the built Bundle
		 * @param copyManager optional copyManager for the built Bundle
		 */
		public BundleBuilder(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager) {
			super(modelStore, objectUri, copyManager);
		}
		
		String context = null;
		
		
		/**
		 * Sets the initial value of context
		 * @parameter context value to set
		 * @return this for chaining
		**/
		public BundleBuilder setContext(String context) {
			this.context = context;
			return this;
		}
	
		
		/**
		 * @return the Bundle
		 * @throws InvalidSPDXAnalysisException on any errors during build
		 */
		public Bundle build() throws InvalidSPDXAnalysisException {
			IModelStoreLock lock = modelStore.enterCriticalSection(false);
			try {
				return new Bundle(this);
			} finally {
				modelStore.leaveCriticalSection(lock);
			}
		}
	}
}
