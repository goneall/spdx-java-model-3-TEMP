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
 
package org.spdx.library.model.v3.security;

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

import org.spdx.library.model.v3.core.ProfileIdentifierType;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * VexUnderInvestigationVulnAssessmentRelationship links a vulnerability to 
 * a number of products stating the vulnerability's impact on them is being investigated. 
 * It represents the VEX under_investigation status. **Constraints** When linking 
 * elements using a VexUnderInvestigationVulnAssessmentRelationship the following 
 * requirements must be observed: - Elements linked with a VexUnderInvestigationVulnAssessmentRelationship 
 * are constrained to using the underInvestigationFor relationship type. - The from: 
 * end of the relationship must ve a /Security/Vulnerability classed element. **Syntax** 
 * ```json { "@type": "VexUnderInvestigationVulnAssessmentRelationship", "@id": 
 * "urn:spdx.dev:vex-underInvestigation-1", "relationshipType": "underInvestigationFor", 
 * "from": "urn:spdx.dev:vuln-cve-2020-28498", "to": ["urn:product-acme-application-1.3"], 
 * "assessedElement": "urn:npm-elliptic-6.5.2", "suppliedBy": ["urn:spdx.dev:agent-jane-doe"], 
 * "publishedTime": "2021-03-09T11:04:53Z" } ``` 
 */
public class VexUnderInvestigationVulnAssessmentRelationship extends VexVulnAssessmentRelationship  {

	
	/**
	 * Create the VexUnderInvestigationVulnAssessmentRelationship with default model store and generated anonymous ID
	 * @throws InvalidSPDXAnalysisException when unable to create the VexUnderInvestigationVulnAssessmentRelationship
	 */
	public VexUnderInvestigationVulnAssessmentRelationship() throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore().getNextId(IdType.Anonymous, null));
	}

	/**
	 * @param objectUri URI or anonymous ID for the VexUnderInvestigationVulnAssessmentRelationship
	 * @throws InvalidSPDXAnalysisException when unable to create the VexUnderInvestigationVulnAssessmentRelationship
	 */
	public VexUnderInvestigationVulnAssessmentRelationship(String objectUri) throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore(), objectUri, DefaultModelStore.getDefaultCopyManager(), true);
	}

	/**
	 * @param modelStore Model store where the VexUnderInvestigationVulnAssessmentRelationship is to be stored
	 * @param objectUri URI or anonymous ID for the VexUnderInvestigationVulnAssessmentRelationship
	 * @param copyManager Copy manager for the VexUnderInvestigationVulnAssessmentRelationship - can be null if copying is not required
	 * @param create true if VexUnderInvestigationVulnAssessmentRelationship is to be created
	 * @throws InvalidSPDXAnalysisException when unable to create the VexUnderInvestigationVulnAssessmentRelationship
	 */
	public VexUnderInvestigationVulnAssessmentRelationship(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager,
			boolean create)	throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create);
	}

	/**
	 * Create the VexUnderInvestigationVulnAssessmentRelationship from the builder - used in the builder class
	 * @param builder Builder to create the VexUnderInvestigationVulnAssessmentRelationship from
	 * @throws InvalidSPDXAnalysisException when unable to create the VexUnderInvestigationVulnAssessmentRelationship
	 */
	protected VexUnderInvestigationVulnAssessmentRelationship(VexUnderInvestigationVulnAssessmentRelationshipBuilder builder) throws InvalidSPDXAnalysisException {
		super(builder);
	}

	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#getType()
	 */
	@Override
	public String getType() {
		return "Security.VexUnderInvestigationVulnAssessmentRelationship";
	}
	
	// Getters and Setters
	
	
	
	@Override
	public String toString() {
		return "VexUnderInvestigationVulnAssessmentRelationship: "+getObjectUri();
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
	
	public static class VexUnderInvestigationVulnAssessmentRelationshipBuilder extends VexVulnAssessmentRelationshipBuilder {
	
		/**
		 * Create an VexUnderInvestigationVulnAssessmentRelationshipBuilder from another model object copying the modelStore and copyManager and using an anonymous ID
		 * @param from model object to copy the model store and copyManager from
		 * @throws InvalidSPDXAnalysisException
		 */
		public VexUnderInvestigationVulnAssessmentRelationshipBuilder(ModelObject from) throws InvalidSPDXAnalysisException {
			this(from, from.getModelStore().getNextId(IdType.Anonymous, null));
		}
	
		/**
		 * Create an VexUnderInvestigationVulnAssessmentRelationshipBuilder from another model object copying the modelStore and copyManager
		 * @param from model object to copy the model store and copyManager from
		 * @param objectUri URI for the object
		 * @param objectUri
		 */
		public VexUnderInvestigationVulnAssessmentRelationshipBuilder(ModelObject from, String objectUri) {
			this(from.getModelStore(), objectUri, from.getCopyManager());
			setStrict(from.isStrict());
		}
		
		/**
		 * Creates a VexUnderInvestigationVulnAssessmentRelationshipBuilder
		 * @param modelStore model store for the built VexUnderInvestigationVulnAssessmentRelationship
		 * @param objectUri objectUri for the built VexUnderInvestigationVulnAssessmentRelationship
		 * @param copyManager optional copyManager for the built VexUnderInvestigationVulnAssessmentRelationship
		 */
		public VexUnderInvestigationVulnAssessmentRelationshipBuilder(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager) {
			super(modelStore, objectUri, copyManager);
		}
		
		
	
		
		/**
		 * @return the VexUnderInvestigationVulnAssessmentRelationship
		 * @throws InvalidSPDXAnalysisException on any errors during build
		 */
		public VexUnderInvestigationVulnAssessmentRelationship build() throws InvalidSPDXAnalysisException {
			IModelStoreLock lock = modelStore.enterCriticalSection(false);
			try {
				return new VexUnderInvestigationVulnAssessmentRelationship(this);
			} finally {
				modelStore.leaveCriticalSection(lock);
			}
		}
	}
}