export declare enum ApiAction {
    NotDefined = "NotDefined",
    Delete = "Delete",
    Get = "Get",
    Head = "Head",
    Options = "Options",
    Patch = "Patch",
    Post = "Post",
    Put = "Put",
}
export declare enum ApiType {
    NotDefined = "NotDefined",
    Private = "Private",
    Internal = "Internal",
    Public = "Public",
}
export declare enum ApplicationType {
    NotDefined = "NotDefined",
    Aad = "Aad",
    Custom = "Custom",
}
export declare enum ApprovableStatus {
    NotDefined = "NotDefined",
    Rejected = "Rejected",
    Draft = "Draft",
    Pending = "Pending",
    Approved = "Approved",
    Completed = "Completed",
    Withdrawn = "Withdrawn",
}
export declare enum AssetType {
    NotDefined = "NotDefined",
    GriffinProcessor = "GriffinProcessor",
    SignalType = "SignalType",
    ApplicationScenario = "ApplicationScenario",
    ApplicationCompliance = "ApplicationCompliance",
    ApplicationSecurity = "ApplicationSecurity",
    GriffinWebService = "GriffinWebService",
    MonitoringSetting = "MonitoringSetting",
    CoreAuthPolicy = "CoreAuthPolicy",
    ScenarioRequest = "ScenarioRequest",
}
export declare enum CertificateStatus {
    NotDefined = "NotDefined",
    Draft = "Draft",
    Pending = "Pending",
    Approved = "Approved",
    Completed = "Completed",
}
export declare enum ChangeType {
    NotDefined = "NotDefined",
    Created = "Created",
    Updated = "Updated",
    Deleted = "Deleted",
    Restored = "Restored",
    Submitted = "Submitted",
    Moved = "Moved",
}
export declare enum EnvironmentType {
    NotDefined = "NotDefined",
    OnBox = "OnBox",
    OffBox = "OffBox",
}
export declare enum YesNoDontKnowType {
    NotDefined = "NotDefined",
    Yes = "Yes",
    No = "No",
    DontKnow = "DontKnow",
}
export declare enum MailboxType {
    NotDefined = "NotDefined",
    ConsumerUser = "ConsumerUser",
    BusinessUser = "BusinessUser",
    ConsumerGroup = "ConsumerGroup",
    BusinessGroup = "BusinessGroup",
}
export declare enum ProcessorExecutionMode {
    NotDefined = "NotDefined",
    Delayed = "Delayed",
    Inline = "Inline",
}
export declare enum ProcessorType {
    NotDefined = "NotDefined",
    Item = "Item",
    Mailbox = "Mailbox",
    Scheduled = "Scheduled",
}
export declare enum RecipientType {
    NotDefined = "NotDefined",
    User = "User",
    Room = "Room",
    Group = "Group",
}
export declare enum RestVersion {
    NotDefined = "NotDefined",
    V1 = "V1",
    V2 = "V2",
}
export declare enum SecurityRoleType {
    NotDefined = "NotDefined",
    GlobalAdmin = "GlobalAdmin",
    SIGSAdmin = "SIGSAdmin",
    GriffinAdmin = "GriffinAdmin",
    SOTAdmin = "SOTAdmin",
    GRCAdmin = "GRCAdmin",
    PartnerAdmin = "PartnerAdmin",
    CoreAuthAdmin = "CoreAuthAdmin",
    MonitoringAdmin = "MonitoringAdmin",
    ScenarioAdmin = "ScenarioAdmin",
    ApplicationAdmin = "ApplicationAdmin",
    ApiAdmin = "ApiAdmin",
}
export declare enum SourceType {
    NotDefined = "NotDefined",
    Core = "Core",
    Griffin = "Griffin",
}
export declare enum VisibilityType {
    NotDefined = "NotDefined",
    Private = "Private",
    Public = "Public",
}
export declare enum EntityLifeCycleStatus {
    NotDefined = "NotDefined",
    Draft = "Draft",
    Active = "Active",
    Retired = "Retired",
}
export declare enum CosmosSSConnectionType {
    ColBased = "ColBased",
    ScopeJobBased = "ScopeJobBased",
}
export declare enum ScopeJobConnectionType {
    JobDependency = "JobDependency",
}
export declare enum MeasureType {
    NotDefined = "NotDefined",
    MonitoringResult = "MonitoringResult",
    UtilizationMetric = "UtilizationMetric",
    UsageMetric = "UsageMetric",
    Rating = "Rating",
}
export interface Node {
    Identifier?: string;
    Name?: string;
    Ttl?: number;
    CreatedDateTime?: string;
    ModifiedDateTime?: string;
    CreatedBy?: string;
    ModifiedBy?: string;
    CreatedByDisplayName?: string;
    ModifiedByDisplayName?: string;
    CreatedByUrl?: string;
    ModifiedByUrl?: string;
    ChildLabels?: string;
    CompletenessScore?: string;
    UsageScore?: string;
    CentralityScore?: string;
}
export interface Container extends Node {
    OwnedByIdentities?: Identity[];
    BelongsToContainer?: Container;
    ContainersBelongsTo?: Container[];
}
export interface Identity extends Node {
    EmailAddress?: string;
    BuildsOwnedBy?: Build[];
    ContainersOwnedBy?: Container[];
    ProcessesOwnedBy?: Process[];
    DataOwnedBy?: Data[];
    DataElementsOwnedBy?: DataElement[];
    TagsOwnedBy?: Tag[];
}
export interface Process extends Node {
    OwnedByIdentities?: Identity[];
    DependsOnData?: Data[];
    DataDependsOn?: Data[];
    MeasuresMeasureFor?: Measure[];
}
export interface Data extends Node {
    Description?: string;
    OwnedByIdentities?: Identity[];
    DependsOnProcesses?: Process[];
    ProcessesDependsOn?: Process[];
    DataElementsBelongsTo?: DataElement[];
    MeasuresMeasureFor?: Measure[];
}
export interface DataElement extends Node {
    Description?: string;
    OwnedByIdentities?: Identity[];
    BelongsToData?: Data;
}
export interface Tag extends Node {
    OwnedByIdentities?: Identity[];
}
export interface Measure extends Node {
    Value?: number;
    IsUnhealthy?: boolean;
    Description?: string;
    Type?: MeasureType;
    OccurredDateTime?: string;
    Data?: string;
    MeasureForProcess?: Process;
    MeasureForData?: Data;
}
export interface Build extends Node {
    Trigger?: string;
    StartDateTime?: string;
    EndDateTime?: string;
    OwnedByIdentities?: Identity[];
}
export interface Scenario extends Tag {
    ProblemToSolve?: string;
    BusinessImpact?: string;
}
export interface Artifact extends Node {
    Value?: string;
}
export interface Owner extends Identity {
    VsoBuildOwnedBy?: VsoBuild;
    CFScenarioOwnedBy?: CFScenario;
    CFEntityOwnedBy?: CFEntity;
    ServiceInstanceOwnedBy?: ServiceInstance;
    DeploymentEnvironmentOwnedBy?: DeploymentEnvironment;
    ComplianceBoundaryOwnedBy?: ComplianceBoundary;
    SiphonTenantOwnedBy?: SiphonTenant;
    AzureHdiSparkClusterOwnedBy?: AzureHdiSparkCluster;
    CassandraClusterOwnedBy?: CassandraCluster;
    CassandraKeyspaceOwnedBy?: CassandraKeyspace;
    DataStreamOwnedBy?: DataStream;
    SparkJobOwnedBy?: SparkJob;
    DatasetOwnedBy?: Dataset;
    DatasetColumnOwnedBy?: DatasetColumn;
}
export interface VsoBuild extends Build {
    BuildNumber?: string;
    Branch?: string;
    VsoProject?: string;
    Repository?: string;
    OwnedByOwners?: Owner[];
    SparkJobsIn?: SparkJob[];
    DatasetsIn?: Dataset[];
    DatasetColumnsIn?: DatasetColumn[];
}
export interface CFScenario extends Scenario {
    DisplayName?: string;
    Status?: string;
    BusinessImpactScore?: number;
    DataInitialSize?: number;
    DataIngestedDailyFrom?: number;
    DataIngestedDailyTo?: number;
    DataRetention?: number;
    OwnedByOwners?: Owner[];
    DataStreamsBelongsTo?: DataStream[];
    SparkJobsBelongsTo?: SparkJob[];
    DatasetsBelongsTo?: Dataset[];
    DatasetColumnsBelongsTo?: DatasetColumn[];
}
export interface CFEntity extends Tag {
    Description?: string;
    DefaultDatasetName?: string;
    AutoGenerate?: boolean;
    Visibility?: number;
    RequiredPartitionKeys?: string[];
    OwnedByOwners?: Owner[];
    DatasetsBelongsTo?: Dataset[];
}
export interface ServiceInstance extends Container {
    OwnedByOwners?: Owner[];
    SiphonTenantsBelongsTo?: SiphonTenant[];
    AzureHdiSparkClustersBelongsTo?: AzureHdiSparkCluster[];
    CassandraClustersBelongsTo?: CassandraCluster[];
}
export interface DeploymentEnvironment extends Container {
    OwnedByOwners?: Owner[];
    SiphonTenantsBelongsTo?: SiphonTenant[];
    AzureHdiSparkClustersBelongsTo?: AzureHdiSparkCluster[];
    CassandraClustersBelongsTo?: CassandraCluster[];
    CassandraKeyspacesBelongsTo?: CassandraKeyspace[];
    DataStreamsBelongsTo?: DataStream[];
    DatasetsBelongsTo?: Dataset[];
    SparkJobsBelongsTo?: SparkJob[];
}
export interface ComplianceBoundary extends Container {
    OwnedByOwners?: Owner[];
    SiphonTenantsBelongsTo?: SiphonTenant[];
    AzureHdiSparkClustersBelongsTo?: AzureHdiSparkCluster[];
    CassandraClustersBelongsTo?: CassandraCluster[];
}
export interface SiphonTenant extends Container {
    PushUrl?: string;
    ContactEmail?: string;
    IsUnhealthy?: boolean;
    BelongsToServiceInstance?: ServiceInstance;
    BelongsToDeploymentEnvironment?: DeploymentEnvironment;
    BelongsToComplianceBoundary?: ComplianceBoundary;
    OwnedByOwners?: Owner[];
    DataStreamsBelongsTo?: DataStream[];
}
export interface AzureHdiSparkCluster extends Container {
    IsUnhealthy?: boolean;
    BelongsToServiceInstance?: ServiceInstance;
    BelongsToDeploymentEnvironment?: DeploymentEnvironment;
    BelongsToComplianceBoundary?: ComplianceBoundary;
    OwnedByOwners?: Owner[];
    SparkJobsBelongsTo?: SparkJob[];
}
export interface CassandraCluster extends Container {
    ContactPoints?: string;
    KeyVaultAppId?: string;
    KeyVaultCertTumbprint?: string;
    KeyVaultPasswordKey?: string;
    KeyVaultUri?: string;
    KeyVaultUsernameKey?: string;
    IsUnhealthy?: boolean;
    BelongsToServiceInstance?: ServiceInstance;
    BelongsToDeploymentEnvironment?: DeploymentEnvironment;
    BelongsToComplianceBoundary?: ComplianceBoundary;
    OwnedByOwners?: Owner[];
    CassandraKeyspacesBelongsTo?: CassandraKeyspace[];
}
export interface CassandraKeyspace extends Container {
    DataClassification?: string;
    IsUnhealthy?: boolean;
    BelongsToCassandraCluster?: CassandraCluster;
    OwnedByOwners?: Owner[];
    BelongsToDeploymentEnvironment?: DeploymentEnvironment;
    DatasetsBelongsTo?: Dataset[];
}
export interface DataStream extends Data {
    Topic?: string;
    RetentionTimeSeconds?: number;
    ContactEmail?: string;
    Originator?: string;
    IsUnhealthy?: boolean;
    BelongsToDeploymentEnvironment?: DeploymentEnvironment;
    BelongsToSiphonTenant?: SiphonTenant;
    BelongsToCFScenarios?: CFScenario[];
    OwnedByOwners?: Owner[];
    SparkJobsDependsOn?: SparkJob[];
    MeasuresMeasureFor?: Measure[];
}
export interface SparkJob extends Process {
    Mode?: string;
    Enabled?: boolean;
    Tier?: string;
    JobPropertiesJson?: string;
    IsUnhealthy?: boolean;
    Type?: string;
    NumberOfExecutors?: string;
    ExecutorMemory?: string;
    DriverMemory?: string;
    Description?: string;
    BelongsToAzureHdiSparkCluster?: AzureHdiSparkCluster;
    BelongsToCFScenarios?: CFScenario[];
    DependsOnDataStreams?: DataStream[];
    DependsOnDatasets?: Dataset[];
    InVsoBuilds?: VsoBuild[];
    OwnedByOwners?: Owner[];
    BelongsToDeploymentEnvironment?: DeploymentEnvironment;
    DatasetsDependsOn?: Dataset[];
    DatasetColumnsDependsOn?: DatasetColumn[];
    MeasuresMeasureFor?: Measure[];
}
export interface Dataset extends Data {
    Table?: string;
    DataClassification?: string;
    Visibility?: string;
    AutoGenerate?: boolean;
    DeprecatedAfter?: string;
    IsUnhealthy?: boolean;
    BelongsToCassandraKeyspace?: CassandraKeyspace;
    BelongsToCFEntity?: CFEntity;
    BelongsToCFScenarios?: CFScenario[];
    DependsOnSparkJobs?: SparkJob[];
    InVsoBuild?: VsoBuild;
    OwnedByOwners?: Owner[];
    BelongsToDeploymentEnvironment?: DeploymentEnvironment;
    SparkJobsDependsOn?: SparkJob[];
    DatasetColumnsBelongsTo?: DatasetColumn[];
    MeasuresMeasureFor?: Measure[];
}
export interface DatasetColumn extends DataElement {
    Alias?: string;
    DataType?: string;
    Sla?: number;
    Freshness?: number;
    Format?: string;
    Publisher?: string;
    Category?: string;
    Status?: string;
    KeyType?: string;
    DataClassification?: string;
    KeyOrder?: number;
    IsUnhealthy?: boolean;
    BelongsToDataset?: Dataset;
    BelongsToCFScenarios?: CFScenario[];
    DependsOnSparkJobs?: SparkJob[];
    InVsoBuild?: VsoBuild;
    OwnedByOwners?: Owner[];
    MeasuresMeasureFor?: Measure[];
}
export interface User extends Identity {
    ExternalIdentifier?: string;
    Title?: string;
    ReportingLineLevel?: number;
    Department?: string;
    ReportsToUser?: User;
    BelongsToTeam?: Team;
    UsersReportsTo?: User[];
    ScopeJobsBelongsTo?: ScopeJob[];
    CosmosSSesBelongsTo?: CosmosSS[];
}
export interface Team extends Identity {
    ExternalIdentifier?: string;
    Hierarchy?: string;
    Description?: string;
    UsersBelongsTo?: User[];
}
export interface Cosmos extends Container {
    ExternalIdentifier?: string;
    VcName?: string;
    ClusterName?: string;
    ScopeJobsRunsIn?: ScopeJob[];
    CosmosSSesStoredIn?: CosmosSS[];
}
export interface CosmosSS extends Data {
    ExternalIdentifier?: string;
    Path?: string;
    BelongsToUser?: User;
    DependsOnScopeJobs?: ScopeJob[];
    StoredInCosmos?: Cosmos;
    HasTagClassificationTags?: ClassificationTag[];
    ColumnsBelongsTo?: Column[];
    ScopeJobsDependsOn?: ScopeJob[];
}
export interface Column extends DataElement {
    ExternalIdentifier?: string;
    Type?: string;
    Position?: number;
    BelongsToCosmosSSes?: CosmosSS[];
    BelongsToAriaEvent?: AriaEvent;
}
export interface ScopeJob extends Process {
    ExternalIdentifier?: string;
    Script?: string;
    BelongsToUser?: User;
    DependsOnCosmosSSes?: CosmosSS[];
    RunsInCosmos?: Cosmos;
    CosmosSSesDependsOn?: CosmosSS[];
}
export interface AriaTenant extends Container {
    TenantId?: string;
    AriaEventsStoredIn?: AriaEvent[];
}
export interface AriaEvent extends Data {
    ExternalIdentifier?: string;
    SampleRate?: string;
    SamplingPolicy?: string;
    InstrumentedBy?: string;
    EventType?: string;
    StoredInAriaTenant?: AriaTenant;
    HasTagClassificationTags?: ClassificationTag[];
    InheritsFromAriaEvents?: AriaEvent[];
    ColumnsBelongsTo?: Column[];
    AriaEventsInheritsFrom?: AriaEvent[];
}
export interface ClassificationTag extends Tag {
    ExternalIdentifier?: string;
    Key?: string;
    Value?: string;
    AriaEventsHasTag?: AriaEvent[];
    CosmosSSesHasTag?: CosmosSS[];
}
export interface LoadCsvProgress extends Tag {
    Value?: string;
}
export interface ServiceTreeBase extends Tag {
    ExternalId?: string;
    Description?: string;
    Status?: EntityLifeCycleStatus;
}
export interface Service extends ServiceTreeBase {
    ExternalFacing?: boolean;
    OwnedByMicrosoft?: boolean;
    Comments?: string;
    BelongsToServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    BelongsToTeamGroup?: TeamGroup;
    BelongsToServiceGroup?: ServiceGroup;
    ProgramManagerOwnerSecurityIdentities?: SecurityIdentity[];
    DeveloperOwnerSecurityIdentities?: SecurityIdentity[];
    SubstrateScenariosAssociatedWith?: SubstrateScenario[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
    ScenarioRequestsAssociatedWith?: ScenarioRequest[];
}
export interface ServiceTreeHierarchyBase extends ServiceTreeBase {
    BusinessOwnerSecurityIdentities?: SecurityIdentity[];
    ServicesBelongsTo?: Service[];
    SubstrateScenariosOwnedBy?: SubstrateScenario[];
    ScenarioRequestsOwnedBy?: ScenarioRequest[];
    ApplicationsTentativeOwnedBy?: Application[];
}
export interface TeamGroup extends ServiceTreeHierarchyBase {
    BelongsToServiceGroup?: ServiceGroup;
    ServicesBelongsTo?: Service[];
}
export interface ServiceGroup extends ServiceTreeHierarchyBase {
    BelongsToOrganization?: Organization;
    ServicesBelongsTo?: Service[];
    TeamGroupsBelongsTo?: TeamGroup[];
}
export interface Organization extends ServiceTreeHierarchyBase {
    BelongsToDivision?: Division;
    ServiceGroupsBelongsTo?: ServiceGroup[];
}
export interface Division extends ServiceTreeHierarchyBase {
    OrganizationsBelongsTo?: Organization[];
}
export interface Partner extends Tag {
    PcCode?: string;
    Division?: string;
    Organization?: string;
    ServiceGroup?: string;
    FinanceOwner?: string;
    Description?: string;
    ApplicationsOwnedBy?: Application[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Comment extends Node {
    Value?: string;
    Status?: ApprovableStatus;
    CommentForApprovable?: Approvable;
}
export interface ApplicationReview extends Approvable {
    BelongsToApplication?: Application;
}
export interface SecurityRole extends Node {
    Type?: SecurityRoleType;
    SecurityIdentitiesIsMemberOf?: SecurityIdentity[];
    SecurityApplicationsIsMemberOf?: SecurityApplication[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface SecurityApplication extends Application {
    IsMemberOfSecurityRoles?: SecurityRole[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface ApplicationSetting extends Approvable {
}
export interface MonitoringSetting extends ApplicationSetting {
    BelongsToApplication?: Application;
}
export interface AccountType extends Tag {
    CoreAuthPolicyTargets?: CoreAuthPolicy;
    ScenarioRequestsTargets?: ScenarioRequest[];
    SubstrateScenariosTargets?: SubstrateScenario[];
}
export interface CoreAuthPolicy extends ApplicationSetting {
    PolicyName?: string;
    PolicyId?: string;
    MajorVersion?: number;
    MinorVersion?: number;
    PolicyVersion?: number;
    Enabled?: boolean;
    IsRbacRequired?: boolean;
    RequiresPop?: boolean;
    GlobalAppTokenEnabled?: boolean;
    MaximumTtlInSeconds?: number;
    BelongsToApplication?: Application;
    TargetsAccountTypes?: AccountType[];
    HasAppOnlyPermissionToPermissions?: Permission[];
    HasActAsPermissionToPermissions?: Permission[];
    HasUserPermissionToPermissions?: Permission[];
    CoreAuthPolicyDeploymentScopesBelongsTo?: CoreAuthPolicyDeploymentScope[];
    CoreAuthPolicyCertificatesBelongsTo?: CoreAuthPolicyCertificate[];
}
export interface CoreAuthPolicyCertificate extends DataElement {
    PublicKey?: string;
    SubjectName?: string;
    ServiceInstanceType?: string;
    CertificateOwnerAlias?: string;
    FullyQualifiedDomainName?: string;
    PfxFileName?: string;
    AkvName?: string;
    AkvCertificateName?: string;
    CertificateType?: string;
    Issuer?: string;
    SubjectAlternativeNames?: string;
    Status?: CertificateStatus;
    CertDojoRequestId?: string;
    BelongsToCoreAuthPolicy?: CoreAuthPolicy;
    EnabledInDeploymentRings?: DeploymentRing[];
}
export interface CoreAuthPolicyDeploymentScope extends Container {
    AuthMetadataUrl?: string;
    IssuerIdentifier?: string;
    BelongsToCoreAuthPolicy?: CoreAuthPolicy;
    EnabledInDeploymentRing?: DeploymentRing;
    FilteredByForests?: Forest[];
}
export interface Approvable extends Node {
    Reason?: string;
    Status?: ApprovableStatus;
    Type?: AssetType;
    ReviewedBy?: string;
    ReviewedDateTime?: string;
    CommentsCommentFor?: Comment[];
}
export interface GriffinProcessor extends Approvable, Process {
    ProcessorGuid?: string;
    ProcessorType?: ProcessorType;
    NotificationURL?: string;
    RestVersion?: RestVersion;
    ProcessorEnvironment?: EnvironmentType;
    MailboxTypes?: MailboxType;
    RecipientTypes?: RecipientType;
    RestItemFilter?: string;
    ProcessingTimeout?: string;
    ChangeType?: ChangeType;
    ExecutionMode?: ProcessorExecutionMode;
    InlineProcesses?: string;
    SerialNumber?: string;
    DependencySortOrder?: string;
    SourceCodePath?: string;
    Description?: string;
    DeployedInDeploymentRings?: DeploymentRing[];
    EnabledInDeploymentRings?: DeploymentRing[];
    InterestedInEntityProperties?: EntityProperty[];
    DependsOnEntities?: Entity[];
    BelongsToApplication?: Application;
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    DependsOnSignalTypes?: SignalType[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface GriffinWebService extends Approvable, Process {
    Description?: string;
    BelongsToApplication?: Application;
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    EntitiesExposedBy?: Entity[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface GriffinApplication extends Application {
}
export interface SignalType extends Approvable, Data {
    IsSyncDedup?: boolean;
    CustomPropertiesSize?: number;
    Volume?: number;
    Retention?: number;
    Description?: string;
    EnumId?: number;
    FlightingChangeRequestId?: string;
    BelongsToApplication?: Application;
    IsOfTypeNgpDataTypes?: NgpDataType[];
    IsOfTypeItemTypes?: ItemType[];
    IsOfTypeDataClassification?: DataClassification;
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    BelongsToSubstrateScenario?: SubstrateScenario;
    CommentMessages?: Message[];
    ApplicationsContributesTo?: Application[];
    PropertySetsBelongsTo?: PropertySet[];
    MeasuresMeasureFor?: Measure[];
    GriffinProcessorsDependsOn?: GriffinProcessor[];
}
export interface NgpDataType extends Tag {
    SignalTypesIsOfType?: SignalType[];
}
export interface ItemType extends Tag {
    SignalTypesIsOfType?: SignalType[];
}
export interface DataClassification extends Tag {
    SignalTypesIsOfType?: SignalType[];
    SignalTypeCustomPropertiesIsOfType?: SignalTypeCustomProperty[];
}
export interface PropertySet extends Tag, Data {
    LastUsedDateTime?: string;
    JsonSample?: string;
    Signature?: string;
    BelongsToSignalType?: SignalType;
    ProducedByApplication?: Application;
    SignalTypeCustomPropertiesUsedIn?: SignalTypeCustomProperty[];
}
export interface SignalTypeCustomProperty extends DataElement {
    DataType?: string;
    Sample?: string;
    UsedInPropertySets?: PropertySet[];
    IsOfTypeDataClassification?: DataClassification;
}
export interface Entity extends Data {
    BaseType?: string;
    SourceType?: SourceType;
    SourceCodePath?: string;
    InternalDocumentationPath?: string;
    ExternalDocumentationPath?: string;
    Visibility?: VisibilityType;
    ExposedByGriffinWebService?: GriffinWebService;
    ApisBelongsTo?: Api[];
    EntityPropertiesBelongsTo?: EntityProperty[];
    PermissionsBelongsTo?: Permission[];
    GriffinProcessorsDependsOn?: GriffinProcessor[];
}
export interface EntityProperty extends DataElement {
    BelongsToEntity?: Entity;
    GriffinProcessorsInterestedIn?: GriffinProcessor[];
}
export interface Api extends Data {
    Action?: ApiAction;
    SourceType?: SourceType;
    SourceCodePath?: string;
    InternalDocumentationPath?: string;
    ExternalDocumentationPath?: string;
    Visibility?: VisibilityType;
    BelongsToEntity?: Entity;
    RequiresPermissions?: Permission[];
    OwnedBySecurityIdentities?: SecurityIdentity[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BugPathAreaPath?: AreaPath;
    GroupEngineeringManagerIdentity?: Identity;
    EngineeringManagerIdentity?: Identity;
    MeasuresMeasureFor?: Measure[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Permission extends Data {
    BelongsToEntity?: Entity;
    ApisRequires?: Api[];
    CoreAuthPolicyHasAppOnlyPermissionTo?: CoreAuthPolicy;
    CoreAuthPolicyHasActAsPermissionTo?: CoreAuthPolicy;
    CoreAuthPolicyHasUserPermissionTo?: CoreAuthPolicy;
}
export interface DeploymentRing extends Container {
    CoreAuthPolicyDeploymentScopeEnabledIn?: CoreAuthPolicyDeploymentScope;
    CoreAuthPolicyCertificatesEnabledIn?: CoreAuthPolicyCertificate[];
    GriffinProcessorsDeployedIn?: GriffinProcessor[];
    GriffinProcessorsEnabledIn?: GriffinProcessor[];
    ForestsBelongsTo?: Forest[];
    MeasuresMeasureFor?: Measure[];
}
export interface Forest extends Container {
    Type?: string;
    Alias?: string;
    Region?: string;
    ServiceInstanceType?: string;
    ActivityState?: string;
    BelongsToDeploymentRings?: DeploymentRing[];
    CoreAuthPolicyDeploymentScopeFilteredBy?: CoreAuthPolicyDeploymentScope;
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface SubstrateScenario extends Scenario {
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    CommentMessages?: Message[];
    AssociatedWithServices?: Service[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    TargetsAccountTypes?: AccountType[];
    ApplicationsBelongsTo?: Application[];
    SignalTypesBelongsTo?: SignalType[];
    ScenarioRequestsContributesTo?: ScenarioRequest[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface File extends Artifact {
    Path?: string;
    ScenarioRequestSupportingDocument?: ScenarioRequest;
}
export interface DesignCategory extends Artifact {
    DesignPatternsBelongsTo?: DesignPattern[];
}
export interface DesignPattern extends Artifact {
    Description?: String;
    DocumentationUrl?: string;
    RequiresDesignPatterns?: DesignPattern[];
    BelongsToDesignCategory?: DesignCategory;
    ScenarioRequestsPattern?: ScenarioRequest[];
    DesignPatternsRequires?: DesignPattern[];
}
export interface ToDo extends Artifact {
    TemplateName?: string;
    Mandatory?: boolean;
    Completed?: boolean;
    CompletedBy?: string;
    CompletedDateTime?: string;
    ScenarioRequestShouldDo?: ScenarioRequest;
    ScenarioRequestMustDo?: ScenarioRequest;
}
export interface Message extends Artifact {
    SignalTypeComment?: SignalType;
    SubstrateScenarioComment?: SubstrateScenario;
    ScenarioRequestComment?: ScenarioRequest;
}
export interface CostModel extends Artifact {
    NbConsumer?: number;
    NbCommercial?: number;
    RU?: number;
    MonetaryValue?: number;
    Currency?: string;
    ScenarioRequestPlannedCogs?: ScenarioRequest;
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface SubstrateScenario extends Scenario {
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    CommentMessages?: Message[];
    AssociatedWithServices?: Service[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    TargetsAccountTypes?: AccountType[];
    ApplicationsBelongsTo?: Application[];
    SignalTypesBelongsTo?: SignalType[];
    ScenarioRequestsContributesTo?: ScenarioRequest[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface SubstrateScenario extends Scenario {
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    CommentMessages?: Message[];
    AssociatedWithServices?: Service[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    TargetsAccountTypes?: AccountType[];
    ApplicationsBelongsTo?: Application[];
    SignalTypesBelongsTo?: SignalType[];
    ScenarioRequestsContributesTo?: ScenarioRequest[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface SubstrateScenario extends Scenario {
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    CommentMessages?: Message[];
    AssociatedWithServices?: Service[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    TargetsAccountTypes?: AccountType[];
    ApplicationsBelongsTo?: Application[];
    SignalTypesBelongsTo?: SignalType[];
    ScenarioRequestsContributesTo?: ScenarioRequest[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface SubstrateScenario extends Scenario {
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    CommentMessages?: Message[];
    AssociatedWithServices?: Service[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    TargetsAccountTypes?: AccountType[];
    ApplicationsBelongsTo?: Application[];
    SignalTypesBelongsTo?: SignalType[];
    ScenarioRequestsContributesTo?: ScenarioRequest[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface SubstrateScenario extends Scenario {
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    CommentMessages?: Message[];
    AssociatedWithServices?: Service[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    TargetsAccountTypes?: AccountType[];
    ApplicationsBelongsTo?: Application[];
    SignalTypesBelongsTo?: SignalType[];
    ScenarioRequestsContributesTo?: ScenarioRequest[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface SubstrateScenario extends Scenario {
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    CommentMessages?: Message[];
    AssociatedWithServices?: Service[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    TargetsAccountTypes?: AccountType[];
    ApplicationsBelongsTo?: Application[];
    SignalTypesBelongsTo?: SignalType[];
    ScenarioRequestsContributesTo?: ScenarioRequest[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface ScenarioRequest extends Approvable {
    WhoAreThey?: string;
    ProblemToSolve?: string;
    BusinessImpact?: string;
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    ExposingApis?: YesNoDontKnowType;
    ApiType?: ApiType;
    InformationProtectionRequirement?: YesNoDontKnowType;
    ContributesToSubstrateScenario?: SubstrateScenario;
    ContactSecurityIdentities?: SecurityIdentity[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    AssociatedWithServices?: Service[];
    ShouldDoToDoes?: ToDo[];
    MustDoToDoes?: ToDo[];
    PatternDesignPatterns?: DesignPattern[];
    CommentMessages?: Message[];
    SupportingDocumentFiles?: File[];
    PlannedCogsCostModel?: CostModel;
    TargetsAccountTypes?: AccountType[];
}
export interface SubstrateScenario extends Scenario {
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    CommentMessages?: Message[];
    AssociatedWithServices?: Service[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    TargetsAccountTypes?: AccountType[];
    ApplicationsBelongsTo?: Application[];
    SignalTypesBelongsTo?: SignalType[];
    ScenarioRequestsContributesTo?: ScenarioRequest[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface Application extends Process {
    Description?: string;
    AppId?: string;
    EscalateTeam?: string;
    FeatureTeam?: string;
    Type?: ApplicationType;
    AadDomain?: string;
    GRCReviewDocumentationUrl?: string;
    ScenarioReviewDocumentationUrl?: string;
    OwnedByPartner?: Partner;
    ContributesToSignalTypes?: SignalType[];
    FeatureTeamIdentity?: Identity;
    EscalateToIdentity?: Identity;
    ContributorIdentities?: Identity[];
    BelongsToSubstrateScenarios?: SubstrateScenario[];
    TentativeOwnedByServiceTreeHierarchyBases?: ServiceTreeHierarchyBase[];
    ApplicationReviewsBelongsTo?: ApplicationReview[];
    SignalTypesBelongsTo?: SignalType[];
    MonitoringSettingBelongsTo?: MonitoringSetting;
    CoreAuthPolicyBelongsTo?: CoreAuthPolicy;
    PropertySetsProducedBy?: PropertySet[];
    GriffinProcessorsBelongsTo?: GriffinProcessor[];
    GriffinWebServicesBelongsTo?: GriffinWebService[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface SubstrateScenario extends Scenario {
    MSProductServiceIntegratedWith?: string;
    GoLiveDate?: string;
    CommentMessages?: Message[];
    AssociatedWithServices?: Service[];
    OwnedByServiceTreeHierarchyBase?: ServiceTreeHierarchyBase;
    TargetsAccountTypes?: AccountType[];
    ApplicationsBelongsTo?: Application[];
    SignalTypesBelongsTo?: SignalType[];
    ScenarioRequestsContributesTo?: ScenarioRequest[];
    SecurityIdentitiesIsAdminOf?: SecurityIdentity[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface SecurityIdentity extends Identity {
    IsAdminOfPartners?: Partner[];
    IsAdminOfApis?: Api[];
    IsAdminOfApplications?: Application[];
    IsAdminOfGriffinProcessors?: GriffinProcessor[];
    IsAdminOfGriffinWebServices?: GriffinWebService[];
    IsMemberOfSecurityRoles?: SecurityRole[];
    IsAdminOfSubstrateScenarios?: SubstrateScenario[];
    IsAdminOfServices?: Service[];
    ApisOwnedBy?: Api[];
    ScenarioRequestsContact?: ScenarioRequest[];
    ServicesProgramManagerOwner?: Service[];
    ServicesDeveloperOwner?: Service[];
    ServiceTreeHierarchyBasesBusinessOwner?: ServiceTreeHierarchyBase[];
}
export interface TestContainer extends Node {
    OwnedByIdentities?: Identity[];
    TestDatasBelongsTo?: TestData[];
}
export interface TestIdentity extends Identity {
    TeamName?: string;
    TestProcessOwnedBy?: TestProcess;
    TestDataOwnedBy?: TestData;
}
export interface TestProcess extends Node {
    OwnedByTestIdentities?: TestIdentity[];
    DependsOnTestDatas?: TestData[];
    TestMeasuresMeasureFor?: TestMeasure[];
}
export interface TestData extends Node {
    Description?: string;
    OwnedByTestIdentities?: TestIdentity[];
    BelongsToTestContainer?: TestContainer;
    TestProcessesDependsOn?: TestProcess[];
    TestMeasureMeasureFor?: TestMeasure;
}
export interface TestTag extends TestData {
    TagName?: string;
}
export interface TestMeasure extends Node {
    TargetName?: string;
    Value?: number;
    IsUnhealthy?: boolean;
    Description?: string;
    Type?: string;
    MeasureForTestProcess?: TestProcess;
    MeasureForTestData?: TestData;
}
export interface TestTagA extends Tag {
    Description?: string;
}
export interface TestTagB extends Tag {
}
export interface Account extends VSO {
    ProjectsBelongsTo?: Project[];
}
export interface Project extends VSO {
    BelongsToAccount?: Account;
    TFSTeamsBelongsTo?: TFSTeam[];
    AreaPathsBelongsTo?: AreaPath[];
}
export interface TFSTeam extends VSO {
    BelongsToProject?: Project;
}
export interface AreaPath extends VSO {
    BelongsToProject?: Project;
    ChildAreaPath?: AreaPath;
    AreaPathsChild?: AreaPath[];
}
export interface VSO extends Tag {
    ExternalId?: string;
}
