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
import org.spdx.library.model.v3.core.PositiveIntegerRange;
import org.spdx.library.model.v3.core.ProfileIdentifierType;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * A Snippet describes a certain part of a file and can be used when the file is known to 
 * have some content that has been included from another original source. Snippets 
 * are useful for denoting when part of a file may have been originally created under 
 * another license or copied from a place with a known vulnerability. 
 */
public class Snippet extends SoftwareArtifact  {

	
	/**
	 * Create the Snippet with default model store and generated anonymous ID
	 * @throws InvalidSPDXAnalysisException when unable to create the Snippet
	 */
	public Snippet() throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore().getNextId(IdType.Anonymous, null));
	}

	/**
	 * @param objectUri URI or anonymous ID for the Snippet
	 * @throws InvalidSPDXAnalysisException when unable to create the Snippet
	 */
	public Snippet(String objectUri) throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore(), objectUri, DefaultModelStore.getDefaultCopyManager(), true);
	}

	/**
	 * @param modelStore Model store where the Snippet is to be stored
	 * @param objectUri URI or anonymous ID for the Snippet
	 * @param copyManager Copy manager for the Snippet - can be null if copying is not required
	 * @param create true if Snippet is to be created
	 * @throws InvalidSPDXAnalysisException when unable to create the Snippet
	 */
	public Snippet(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager,
			boolean create)	throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create);
	}

	/**
	 * Create the Snippet from the builder - used in the builder class
	 * @param builder Builder to create the Snippet from
	 * @throws InvalidSPDXAnalysisException when unable to create the Snippet
	 */
	protected Snippet(SnippetBuilder builder) throws InvalidSPDXAnalysisException {
		super(builder);
		setLineRange(builder.lineRange);
		setSnippetFromFile(builder.snippetFromFile);
		setByteRange(builder.byteRange);
	}

	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#getType()
	 */
	@Override
	public String getType() {
		return "Software.Snippet";
	}
	
	// Getters and Setters
	

		/**
	 * @return the lineRange
	 */
	 @SuppressWarnings("unchecked")
	public Optional<PositiveIntegerRange> getLineRange() throws InvalidSPDXAnalysisException {
		Optional<Object> retval = getObjectPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_LINE_RANGE);
		if (retval.isPresent()) {
			if (!(retval.get() instanceof PositiveIntegerRange)) {
				throw new InvalidSPDXAnalysisException("Incorrect type stored for ");
			}
			return (Optional<PositiveIntegerRange>)(Optional<?>)(retval);
		} else {
			return Optional.empty();
		}
	}
	
	/**
	 * @param lineRange the lineRange to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public Snippet setLineRange(@Nullable PositiveIntegerRange lineRange) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_LINE_RANGE, lineRange);
		return this;
	}

	/**
	 * @return the snippetFromFile
	 */
	 @SuppressWarnings("unchecked")
	public @Nullable SpdxFile getSnippetFromFile() throws InvalidSPDXAnalysisException {
		Optional<Object> retval = getObjectPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_SNIPPET_FROM_FILE);
		if (retval.isPresent()) {
			if (!(retval.get() instanceof SpdxFile)) {
				throw new InvalidSPDXAnalysisException("Incorrect type stored for ");
			}
			return (SpdxFile)(retval.get());
		} else {
			return null;
		}
	}
		
	/**
	 * @param snippetFromFile the snippetFromFile to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public Snippet setSnippetFromFile(@Nullable SpdxFile snippetFromFile) throws InvalidSPDXAnalysisException {
		if (isStrict() && Objects.isNull(snippetFromFile)) {
			throw new InvalidSPDXAnalysisException("snippetFromFile is a required property");
		}
		setPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_SNIPPET_FROM_FILE, snippetFromFile);
		return this;
	}

		/**
	 * @return the byteRange
	 */
	 @SuppressWarnings("unchecked")
	public Optional<PositiveIntegerRange> getByteRange() throws InvalidSPDXAnalysisException {
		Optional<Object> retval = getObjectPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_BYTE_RANGE);
		if (retval.isPresent()) {
			if (!(retval.get() instanceof PositiveIntegerRange)) {
				throw new InvalidSPDXAnalysisException("Incorrect type stored for ");
			}
			return (Optional<PositiveIntegerRange>)(Optional<?>)(retval);
		} else {
			return Optional.empty();
		}
	}
	
	/**
	 * @param byteRange the byteRange to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public Snippet setByteRange(@Nullable PositiveIntegerRange byteRange) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.SOFTWARE_PROP_BYTE_RANGE, byteRange);
		return this;
	}
	
	
	@Override
	public String toString() {
		return "Snippet: "+getObjectUri();
	}
	
	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#_verify(java.util.List)
	 */
	@Override
	public List<String> _verify(Set<String> verifiedIds, String specVersionForVerify, List<ProfileIdentifierType> profiles) {
		List<String> retval = new ArrayList<>();
		retval.addAll(super._verify(verifiedIds, specVersionForVerify, profiles));
		Optional<PositiveIntegerRange> lineRange;
		try {
			lineRange = getLineRange();
			if (lineRange.isPresent()) {
				retval.addAll(lineRange.get().verify(verifiedIds, specVersionForVerify, profiles));
			}
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting lineRange for Snippet: "+e.getMessage());
		}
		SpdxFile snippetFromFile;
		try {
			snippetFromFile = getSnippetFromFile();
			if (Objects.nonNull(snippetFromFile)) {
				retval.addAll(snippetFromFile.verify(verifiedIds, specVersionForVerify, profiles));
			} else if (!Collections.disjoint(profiles, Arrays.asList(new ProfileIdentifierType[] { ProfileIdentifierType.SOFTWARE }))) {
					retval.add("Missing snippetFromFile in Snippet");
			}
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting snippetFromFile for Snippet: "+e.getMessage());
		}
		Optional<PositiveIntegerRange> byteRange;
		try {
			byteRange = getByteRange();
			if (byteRange.isPresent()) {
				retval.addAll(byteRange.get().verify(verifiedIds, specVersionForVerify, profiles));
			}
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting byteRange for Snippet: "+e.getMessage());
		}
		return retval;
	}
	
	public static class SnippetBuilder extends SoftwareArtifactBuilder {
	
		/**
		 * Create an SnippetBuilder from another model object copying the modelStore and copyManager and using an anonymous ID
		 * @param from model object to copy the model store and copyManager from
		 * @throws InvalidSPDXAnalysisException
		 */
		public SnippetBuilder(ModelObject from) throws InvalidSPDXAnalysisException {
			this(from, from.getModelStore().getNextId(IdType.Anonymous, null));
		}
	
		/**
		 * Create an SnippetBuilder from another model object copying the modelStore and copyManager
		 * @param from model object to copy the model store and copyManager from
		 * @param objectUri URI for the object
		 * @param objectUri
		 */
		public SnippetBuilder(ModelObject from, String objectUri) {
			this(from.getModelStore(), objectUri, from.getCopyManager());
			setStrict(from.isStrict());
		}
		
		/**
		 * Creates a SnippetBuilder
		 * @param modelStore model store for the built Snippet
		 * @param objectUri objectUri for the built Snippet
		 * @param copyManager optional copyManager for the built Snippet
		 */
		public SnippetBuilder(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager) {
			super(modelStore, objectUri, copyManager);
		}
		
		PositiveIntegerRange lineRange = null;
		SpdxFile snippetFromFile = null;
		PositiveIntegerRange byteRange = null;
		
		
		/**
		 * Sets the initial value of lineRange
		 * @parameter lineRange value to set
		 * @return this for chaining
		**/
		public SnippetBuilder setLineRange(PositiveIntegerRange lineRange) {
			this.lineRange = lineRange;
			return this;
		}
		
		/**
		 * Sets the initial value of snippetFromFile
		 * @parameter snippetFromFile value to set
		 * @return this for chaining
		**/
		public SnippetBuilder setSnippetFromFile(SpdxFile snippetFromFile) {
			this.snippetFromFile = snippetFromFile;
			return this;
		}
		
		/**
		 * Sets the initial value of byteRange
		 * @parameter byteRange value to set
		 * @return this for chaining
		**/
		public SnippetBuilder setByteRange(PositiveIntegerRange byteRange) {
			this.byteRange = byteRange;
			return this;
		}
	
		
		/**
		 * @return the Snippet
		 * @throws InvalidSPDXAnalysisException on any errors during build
		 */
		public Snippet build() throws InvalidSPDXAnalysisException {
			IModelStoreLock lock = modelStore.enterCriticalSection(false);
			try {
				return new Snippet(this);
			} finally {
				modelStore.leaveCriticalSection(lock);
			}
		}
	}
}
