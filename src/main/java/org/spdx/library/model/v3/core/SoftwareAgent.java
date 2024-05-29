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
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.IModelStore.IModelStoreLock;


/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * A SoftwareAgent is a software program that is given the authority (similar to a user's 
 * authority) to act on a system. 
 */
public class SoftwareAgent extends Agent  {

	
	/**
	 * Create the SoftwareAgent with default model store and generated anonymous ID
	 * @throws InvalidSPDXAnalysisException when unable to create the SoftwareAgent
	 */
	public SoftwareAgent() throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore().getNextId(IdType.Anonymous, null));
	}

	/**
	 * @param objectUri URI or anonymous ID for the SoftwareAgent
	 * @throws InvalidSPDXAnalysisException when unable to create the SoftwareAgent
	 */
	public SoftwareAgent(String objectUri) throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore(), objectUri, DefaultModelStore.getDefaultCopyManager(), true);
	}

	/**
	 * @param modelStore Model store where the SoftwareAgent is to be stored
	 * @param objectUri URI or anonymous ID for the SoftwareAgent
	 * @param copyManager Copy manager for the SoftwareAgent - can be null if copying is not required
	 * @param create true if SoftwareAgent is to be created
	 * @throws InvalidSPDXAnalysisException when unable to create the SoftwareAgent
	 */
	public SoftwareAgent(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager,
			boolean create)	throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create);
	}

	/**
	 * Create the SoftwareAgent from the builder - used in the builder class
	 * @param builder Builder to create the SoftwareAgent from
	 * @throws InvalidSPDXAnalysisException when unable to create the SoftwareAgent
	 */
	protected SoftwareAgent(SoftwareAgentBuilder builder) throws InvalidSPDXAnalysisException {
		super(builder);
	}

	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#getType()
	 */
	@Override
	public String getType() {
		return "Core.SoftwareAgent";
	}
	
	// Getters and Setters
	
	
	
	@Override
	public String toString() {
		return "SoftwareAgent: "+getObjectUri();
	}
	
	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#_verify(java.util.List)
	 */
	@Override
	public List<String> _verify(Set<String> verifiedIds, String specVersionForVerify, List<ProfileIdentifierType> profiles) {
		List<String> retval = new ArrayList<>();
		retval.addAll(super._verify(verifiedIds, specVersionForVerify, profiles));
		return retval;
	}
	
	public static class SoftwareAgentBuilder extends AgentBuilder {
	
		/**
		 * Create an SoftwareAgentBuilder from another model object copying the modelStore and copyManager and using an anonymous ID
		 * @param from model object to copy the model store and copyManager from
		 * @throws InvalidSPDXAnalysisException
		 */
		public SoftwareAgentBuilder(ModelObject from) throws InvalidSPDXAnalysisException {
			this(from, from.getModelStore().getNextId(IdType.Anonymous, null));
		}
	
		/**
		 * Create an SoftwareAgentBuilder from another model object copying the modelStore and copyManager
		 * @param from model object to copy the model store and copyManager from
		 * @param objectUri URI for the object
		 * @param objectUri
		 */
		public SoftwareAgentBuilder(ModelObject from, String objectUri) {
			this(from.getModelStore(), objectUri, from.getCopyManager());
			setStrict(from.isStrict());
		}
		
		/**
		 * Creates a SoftwareAgentBuilder
		 * @param modelStore model store for the built SoftwareAgent
		 * @param objectUri objectUri for the built SoftwareAgent
		 * @param copyManager optional copyManager for the built SoftwareAgent
		 */
		public SoftwareAgentBuilder(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager) {
			super(modelStore, objectUri, copyManager);
		}
		
		
	
		
		/**
		 * @return the SoftwareAgent
		 * @throws InvalidSPDXAnalysisException on any errors during build
		 */
		public SoftwareAgent build() throws InvalidSPDXAnalysisException {
			IModelStoreLock lock = modelStore.enterCriticalSection(false);
			try {
				return new SoftwareAgent(this);
			} finally {
				modelStore.leaveCriticalSection(lock);
			}
		}
	}
}
