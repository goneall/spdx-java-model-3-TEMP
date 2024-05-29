/**
 * Copyright (c) 2023 Source Auditor Inc.
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

package org.spdx.library.model.v3;

import org.spdx.core.IModelCopyManager;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.storage.IModelStore;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;


/**
 * Factory class for creating model classes.
 * 
 * The <code>getModelObject</code> method will fetch or create a model object based on the URI for the class
 * 
 * @author Gary O'Neall
 *
 */
public class SpdxModelClassFactory {

	public static Map<String, Class<?>> SPDX_TYPE_TO_CLASS_V3;
	public static Map<Class<?>, String> SPDX_CLASS_TO_TYPE;
	static {
		Map<String, Class<?>> typeToClassV3 = new HashMap<>();
		
		typeToClassV3.put(SpdxConstantsV3.CORE_DICTIONARY_ENTRY, org.spdx.library.model.v3.core.DictionaryEntry.class);
		typeToClassV3.put(SpdxConstantsV3.SIMPLE_LICENSING_LICENSE_EXPRESSION, org.spdx.library.model.v3.simplelicensing.LicenseExpression.class);
		typeToClassV3.put(SpdxConstantsV3.DATASET_CONFIDENTIALITY_LEVEL_TYPE, org.spdx.library.model.v3.dataset.ConfidentialityLevelType.class);
		typeToClassV3.put(SpdxConstantsV3.A_I_SAFETY_RISK_ASSESSMENT_TYPE, org.spdx.library.model.v3.ai.SafetyRiskAssessmentType.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_BOM, org.spdx.library.model.v3.core.Bom.class);
		typeToClassV3.put(SpdxConstantsV3.EXPANDED_LICENSING_OR_LATER_OPERATOR, org.spdx.library.model.v3.expandedlicensing.OrLaterOperator.class);
		typeToClassV3.put(SpdxConstantsV3.SIMPLE_LICENSING_SIMPLE_LICENSING_TEXT, org.spdx.library.model.v3.simplelicensing.SimpleLicensingText.class);
		typeToClassV3.put(SpdxConstantsV3.EXPANDED_LICENSING_LICENSE, org.spdx.library.model.v3.expandedlicensing.License.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_ANNOTATION, org.spdx.library.model.v3.core.Annotation.class);
		typeToClassV3.put(SpdxConstantsV3.SOFTWARE_SPDX_FILE, org.spdx.library.model.v3.software.SpdxFile.class);
		typeToClassV3.put(SpdxConstantsV3.EXPANDED_LICENSING_LISTED_LICENSE_EXCEPTION, org.spdx.library.model.v3.expandedlicensing.ListedLicenseException.class);
		typeToClassV3.put(SpdxConstantsV3.EXPANDED_LICENSING_LICENSE_ADDITION, org.spdx.library.model.v3.expandedlicensing.LicenseAddition.class);
		typeToClassV3.put(SpdxConstantsV3.SOFTWARE_SOFTWARE_ARTIFACT, org.spdx.library.model.v3.software.SoftwareArtifact.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_VEX_AFFECTED_VULN_ASSESSMENT_RELATIONSHIP, org.spdx.library.model.v3.security.VexAffectedVulnAssessmentRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.DATASET_DATASET, org.spdx.library.model.v3.dataset.Dataset.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_SSVC_VULN_ASSESSMENT_RELATIONSHIP, org.spdx.library.model.v3.security.SsvcVulnAssessmentRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_INTEGRITY_METHOD, org.spdx.library.model.v3.core.IntegrityMethod.class);
		typeToClassV3.put(SpdxConstantsV3.SOFTWARE_SNIPPET, org.spdx.library.model.v3.software.Snippet.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_EXTENSION, org.spdx.library.model.v3.core.Extension.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_EPSS_VULN_ASSESSMENT_RELATIONSHIP, org.spdx.library.model.v3.security.EpssVulnAssessmentRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.SOFTWARE_SBOM_TYPE, org.spdx.library.model.v3.software.SbomType.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_TOOL, org.spdx.library.model.v3.core.Tool.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_EXTERNAL_REF, org.spdx.library.model.v3.core.ExternalRef.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_EXTERNAL_IDENTIFIER, org.spdx.library.model.v3.core.ExternalIdentifier.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_ELEMENT_COLLECTION, org.spdx.library.model.v3.core.ElementCollection.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_ANNOTATION_TYPE, org.spdx.library.model.v3.core.AnnotationType.class);
		typeToClassV3.put(SpdxConstantsV3.SOFTWARE_SOFTWARE_DEPENDENCY_RELATIONSHIP, org.spdx.library.model.v3.software.SoftwareDependencyRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_VEX_JUSTIFICATION_TYPE, org.spdx.library.model.v3.security.VexJustificationType.class);
		typeToClassV3.put(SpdxConstantsV3.A_I_A_I_PACKAGE, org.spdx.library.model.v3.ai.AIPackage.class);
		typeToClassV3.put(SpdxConstantsV3.EXPANDED_LICENSING_CONJUNCTIVE_LICENSE_SET, org.spdx.library.model.v3.expandedlicensing.ConjunctiveLicenseSet.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_EXTERNAL_REF_TYPE, org.spdx.library.model.v3.core.ExternalRefType.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_EXPLOIT_CATALOG_TYPE, org.spdx.library.model.v3.security.ExploitCatalogType.class);
		typeToClassV3.put(SpdxConstantsV3.SOFTWARE_SOFTWARE_PURPOSE, org.spdx.library.model.v3.software.SoftwarePurpose.class);
		typeToClassV3.put(SpdxConstantsV3.EXPANDED_LICENSING_CUSTOM_LICENSE_ADDITION, org.spdx.library.model.v3.expandedlicensing.CustomLicenseAddition.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_ELEMENT, org.spdx.library.model.v3.core.Element.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_PERSON, org.spdx.library.model.v3.core.Person.class);
		typeToClassV3.put(SpdxConstantsV3.SOFTWARE_DEPENDENCY_CONDITIONALITY_TYPE, org.spdx.library.model.v3.software.DependencyConditionalityType.class);
		typeToClassV3.put(SpdxConstantsV3.DATASET_DATASET_AVAILABILITY_TYPE, org.spdx.library.model.v3.dataset.DatasetAvailabilityType.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_EXTERNAL_MAP, org.spdx.library.model.v3.core.ExternalMap.class);
		typeToClassV3.put(SpdxConstantsV3.EXPANDED_LICENSING_LISTED_LICENSE, org.spdx.library.model.v3.expandedlicensing.ListedLicense.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_VULN_ASSESSMENT_RELATIONSHIP, org.spdx.library.model.v3.security.VulnAssessmentRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_AGENT, org.spdx.library.model.v3.core.Agent.class);
		typeToClassV3.put(SpdxConstantsV3.SOFTWARE_SPDX_PACKAGE, org.spdx.library.model.v3.software.SpdxPackage.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_EXTERNAL_IDENTIFIER_TYPE, org.spdx.library.model.v3.core.ExternalIdentifierType.class);
		typeToClassV3.put(SpdxConstantsV3.SOFTWARE_SOFTWARE_DEPENDENCY_LINK_TYPE, org.spdx.library.model.v3.software.SoftwareDependencyLinkType.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_POSITIVE_INTEGER_RANGE, org.spdx.library.model.v3.core.PositiveIntegerRange.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_PRESENCE_TYPE, org.spdx.library.model.v3.core.PresenceType.class);
		typeToClassV3.put(SpdxConstantsV3.EXPANDED_LICENSING_DISJUNCTIVE_LICENSE_SET, org.spdx.library.model.v3.expandedlicensing.DisjunctiveLicenseSet.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_HASH, org.spdx.library.model.v3.core.Hash.class);
		typeToClassV3.put(SpdxConstantsV3.DATASET_DATASET_TYPE, org.spdx.library.model.v3.dataset.DatasetType.class);
		typeToClassV3.put(SpdxConstantsV3.EXPANDED_LICENSING_CUSTOM_LICENSE, org.spdx.library.model.v3.expandedlicensing.CustomLicense.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_SPDX_DOCUMENT, org.spdx.library.model.v3.core.SpdxDocument.class);
		typeToClassV3.put(SpdxConstantsV3.SIMPLE_LICENSING_ANY_LICENSE_INFO, org.spdx.library.model.v3.simplelicensing.AnyLicenseInfo.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_VEX_VULN_ASSESSMENT_RELATIONSHIP, org.spdx.library.model.v3.security.VexVulnAssessmentRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_CVSS_V2_VULN_ASSESSMENT_RELATIONSHIP, org.spdx.library.model.v3.security.CvssV2VulnAssessmentRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.EXPANDED_LICENSING_WITH_ADDITION_OPERATOR, org.spdx.library.model.v3.expandedlicensing.WithAdditionOperator.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_BUNDLE, org.spdx.library.model.v3.core.Bundle.class);
		typeToClassV3.put(SpdxConstantsV3.SOFTWARE_SBOM, org.spdx.library.model.v3.software.Sbom.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_LIFECYCLE_SCOPE_TYPE, org.spdx.library.model.v3.core.LifecycleScopeType.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_VEX_UNDER_INVESTIGATION_VULN_ASSESSMENT_RELATIONSHIP, org.spdx.library.model.v3.security.VexUnderInvestigationVulnAssessmentRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_VEX_FIXED_VULN_ASSESSMENT_RELATIONSHIP, org.spdx.library.model.v3.security.VexFixedVulnAssessmentRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_HASH_ALGORITHM, org.spdx.library.model.v3.core.HashAlgorithm.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_EXPLOIT_CATALOG_VULN_ASSESSMENT_RELATIONSHIP, org.spdx.library.model.v3.security.ExploitCatalogVulnAssessmentRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_SOFTWARE_AGENT, org.spdx.library.model.v3.core.SoftwareAgent.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_CREATION_INFO, org.spdx.library.model.v3.core.CreationInfo.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_CVSS_V3_VULN_ASSESSMENT_RELATIONSHIP, org.spdx.library.model.v3.security.CvssV3VulnAssessmentRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_ORGANIZATION, org.spdx.library.model.v3.core.Organization.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_RELATIONSHIP, org.spdx.library.model.v3.core.Relationship.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_RELATIONSHIP_TYPE, org.spdx.library.model.v3.core.RelationshipType.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_RELATIONSHIP_COMPLETENESS, org.spdx.library.model.v3.core.RelationshipCompleteness.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_ARTIFACT, org.spdx.library.model.v3.core.Artifact.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_LIFECYCLE_SCOPED_RELATIONSHIP, org.spdx.library.model.v3.core.LifecycleScopedRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_VEX_NOT_AFFECTED_VULN_ASSESSMENT_RELATIONSHIP, org.spdx.library.model.v3.security.VexNotAffectedVulnAssessmentRelationship.class);
		typeToClassV3.put(SpdxConstantsV3.CORE_PROFILE_IDENTIFIER_TYPE, org.spdx.library.model.v3.core.ProfileIdentifierType.class);
		typeToClassV3.put(SpdxConstantsV3.BUILD_BUILD, org.spdx.library.model.v3.build.Build.class);
		typeToClassV3.put(SpdxConstantsV3.EXPANDED_LICENSING_EXTENDABLE_LICENSE, org.spdx.library.model.v3.expandedlicensing.ExtendableLicense.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_SSVC_DECISION_TYPE, org.spdx.library.model.v3.security.SsvcDecisionType.class);
		typeToClassV3.put(SpdxConstantsV3.SECURITY_VULNERABILITY, org.spdx.library.model.v3.security.Vulnerability.class);
		
		SPDX_TYPE_TO_CLASS_V3 = Collections.unmodifiableMap(typeToClassV3);
		
		Map<Class<?>, String> classToType = new HashMap<>();
		for (Entry<String, Class<?>> entry:typeToClassV3.entrySet()) {
			classToType.put(entry.getValue(), entry.getKey());
		}
		
		SPDX_CLASS_TO_TYPE = Collections.unmodifiableMap(classToType);
	}
	
	/**
	 * Create an SPDX spec version 3.0 model object in a model store given the URI for the object
	 * @param modelStore model store where the object is to be created
	 * @param objectUri URI for the object
	 * @param type SPDX class or type
	 * @param copyManager if non-null, allows for copying of properties from other model stores or document URI's when referenced
	 * @param create if true, create the model object if it does not already exist
	 * @return a ModelObject of type type
	 * @throws InvalidSPDXAnalysisException
	 */
	public static ModelObjectV3 getModelObject(IModelStore modelStore, String objectUri,
			String type, IModelCopyManager copyManager, boolean create) throws InvalidSPDXAnalysisException {
		Objects.requireNonNull(modelStore, "Model store can not be null");
		Objects.requireNonNull(objectUri, "The object URI most not be null");
		
		Class<?> clazz = SPDX_TYPE_TO_CLASS_V3.get(type);
		if (Objects.isNull(clazz)) {
			throw new InvalidSPDXAnalysisException("Unknown SPDX version 3 type: "+type);
		}
		if (Modifier.isAbstract(clazz.getModifiers())) {
			throw new InvalidSPDXAnalysisException("Can not instantiate an abstract class for the SPDX version 3 type: "+type);
		}
		try {
			Constructor<?> con = clazz.getDeclaredConstructor(IModelStore.class, String.class, IModelCopyManager.class, boolean.class);
			return (ModelObjectV3)con.newInstance(modelStore, objectUri, copyManager, create);
		} catch (NoSuchMethodException e) {
			throw new InvalidSPDXAnalysisException("Could not create the model object SPDX version 3 type: "+type);
		} catch (SecurityException e) {
			throw new InvalidSPDXAnalysisException("Unexpected security exception for SPDX version 3 type: "+type, e);
		} catch (InstantiationException e) {
			throw new InvalidSPDXAnalysisException("Unexpected instantiation exception for SPDX version 3 type: "+type, e);
		} catch (IllegalAccessException e) {
			throw new InvalidSPDXAnalysisException("Unexpected illegal access exception for SPDX version 3 type: "+type, e);
		} catch (IllegalArgumentException e) {
			throw new InvalidSPDXAnalysisException("Unexpected illegal argument exception for SPDX version 3 type: "+type, e);
		} catch (InvocationTargetException e) {
			if (e.getTargetException() instanceof InvalidSPDXAnalysisException) {
				throw (InvalidSPDXAnalysisException)e.getTargetException();
			} else {
				throw new InvalidSPDXAnalysisException("Unexpected invocation target exception for SPDX version 2 type: "+type, e);
			}
		}
	}
}
