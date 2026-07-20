// Verbatim mirror of https://www.cheatoffsets.com/g/fortnite (2026-07-20).
// Ground-truth reference: if autogen offsets.h ever regresses, cross-check here.
// Fortnite-specific classes (AFort*, UFort*) live here since cheatoffsets'
// public parser sometimes drops them from its structured tree.
//
// Owner: viru. Do not hand-edit — replace wholesale on each dump.

#pragma once
#include <cstdint>

namespace off::v {

    // ---------- Math primitives ------------------------------------------------
    struct f_vector             { static constexpr std::uintptr_t X=0x0, Y=0x8, Z=0x10; };
    struct f_vector2d           { static constexpr std::uintptr_t X=0x0, Y=0x8; };
    struct f_vector4            { static constexpr std::uintptr_t X=0x0, Y=0x8, Z=0x10, W=0x18; };
    struct f_rotator            { static constexpr std::uintptr_t Pitch=0x0, Yaw=0x8, Roll=0x10; };
    struct f_quat               { static constexpr std::uintptr_t X=0x0, Y=0x8, Z=0x10, W=0x18; };
    struct f_transform          { static constexpr std::uintptr_t Rotation=0x0, Translation=0x20, Scale3D=0x40; };
    struct f_matrix             { static constexpr std::uintptr_t XPlane=0x0, YPlane=0x20, ZPlane=0x40, WPlane=0x60; };
    struct f_color              { static constexpr std::uintptr_t B=0x0, G=0x1, R=0x2, A=0x3; };
    struct f_linear_color       { static constexpr std::uintptr_t R=0x0, G=0x4, B=0x8, A=0xc; };
    struct f_box                { static constexpr std::uintptr_t min=0x0, max=0x18, IsValid=0x30; };
    struct f_box_sphere_bounds  { static constexpr std::uintptr_t origin=0x0, BoxExtent=0x18, SphereRadius=0x30; };
    struct f_int_point          { static constexpr std::uintptr_t X=0x0, Y=0x4; };
    struct f_int_vector         { static constexpr std::uintptr_t X=0x0, Y=0x4, Z=0x8; };

    // ---------- Camera / view --------------------------------------------------
    struct f_minimal_view_info {
        static constexpr std::uintptr_t Location=0x0, Rotation=0x18, FOV=0x30, DesiredFOV=0x34,
            FirstPersonFOV=0x38, FirstPersonScale=0x3c, OrthoWidth=0x40, AspectRatio=0x5c,
            ProjectionMode=0x6c, PostProcessBlendWeight=0x70;
    };
    struct f_camera_cache_entry { static constexpr std::uintptr_t Timestamp=0x0, POV=0x10; };

    struct f_rep_movement {
        static constexpr std::uintptr_t LinearVelocity=0x0, AngularVelocity=0x18, Location=0x30,
            Rotation=0x48, Acceleration=0x60, ServerFrame=0x7c, ServerPhysicsHandle=0x80;
    };
    struct f_based_movement_info {
        static constexpr std::uintptr_t BaseID=0x0, BoneName=0x4, MovementBase=0x8,
            Location=0x10, Rotation=0x28, MovementBaseInterfaceData=0x40;
    };

    // ---------- Engine / world -------------------------------------------------
    struct u_engine {
        static constexpr std::uintptr_t TinyFont=0x30, SmallFont=0x50, LargeFont=0x90,
            ConsoleClass=0x110, GameViewportClientClass=0x130, LocalPlayerClass=0x150;
    };
    struct u_game_engine {
        static constexpr std::uintptr_t GameInstance=0x288, MaxDeltaTime=0x10f8, ServerFlushLogInterval=0x10fc;
    };
    struct u_world {
        static constexpr std::uintptr_t PersistentLevel=0x38, NetDriver=0x40, LineBatcher=0x48,
            PersistentLineBatcher=0x50, ForegroundLineBatcher=0x58, NetworkManager=0x60,
            PhysicsCollisionHandler=0x68, PhysicsQueryHandler=0x70, ExtraReferencedObjects=0x78,
            PerModuleDataObjects=0x88, StreamingLevels=0xa8, StreamingLevelsToConsider=0xb8,
            ServerStreamingLevelsVisibility=0xe0, StreamingLevelsPrefix=0xe8, LineBatchers=0x108,
            MakingVisibleLevels=0x138, MakingInvisibleLevels=0x148, DemoNetDriver=0x158,
            MyParticleEventManager=0x160, DefaultPhysicsVolume=0x168;
    };
    struct u_level {
        static constexpr std::uintptr_t OwningWorld=0x70, Model=0x78, ModelComponents=0x80,
            LevelScriptActor=0xa0, StaticNavigableGeometry=0xd0, LevelBuildDataId=0x228,
            MapBuildData=0x238;
    };
    struct u_game_instance {
        static constexpr std::uintptr_t LocalPlayers=0x38, OnlineSession=0x48, ReferencedObjects=0x50;
    };
    struct u_game_viewport_client {
        static constexpr std::uintptr_t ViewportConsole=0x40, MaxSplitscreenPlayers=0x68,
            World=0x78, GameInstance=0x80;
    };
    struct u_local_player {
        static constexpr std::uintptr_t ViewportClient=0x78, AspectRatioAxisConstraint=0xb8,
            PendingLevelPlayerControllerClass=0xc0, ViewportClientOverride=0xe0, ControllerId=0xe8;
    };

    // ---------- Actor / pawn / controller (base) ------------------------------
    struct a_actor {
        static constexpr std::uintptr_t PrimaryActorTick=0x28,
            bAlwaysRelevant=0x58, bHidden=0x58, bNetTemporary=0x58;
    };
    struct a_pawn {
        static constexpr std::uintptr_t BaseEyeHeight=0x27c, PlayerState=0x290, LastHitBy=0x298,
            Controller=0x2a0, PreviousController=0x2a8, ControlInputVector=0x2b8, LastControlInputVector=0x2d0;
    };
    struct a_character {
        static constexpr std::uintptr_t Mesh=0x2f0, CharacterMovement=0x2f8, CapsuleComponent=0x300,
            BasedMovement=0x308, ReplicatedBasedMovement=0x360,
            ReplicatedServerLastTransformUpdateTimeStamp=0x3b8, BaseRotationOffset=0x3c0,
            BaseTranslationOffset=0x3e0, ReplicatedGravityDirection=0x3f8,
            AnimRootMotionTranslationScale=0x428, CrouchedEyeHeight=0x42c;
    };
    struct a_controller {
        static constexpr std::uintptr_t PlayerState=0x278, StateName=0x2a8, Pawn=0x2b0,
            Character=0x2c0, TransformComponent=0x2c8, ControlRotation=0x2e8;
    };
    struct a_player_controller {
        static constexpr std::uintptr_t player=0x310, AcknowledgedPawn=0x318, MyHUD=0x320,
            PlayerCameraManager=0x328, TargetViewRotation=0x340, HiddenActors=0x378,
            HiddenPrimitiveComponents=0x388, LastSpectatorSyncLocation=0x3a0,
            LastSpectatorSyncRotation=0x3b8, CheatManager=0x3d8, PlayerInput=0x3e8, NetPlayerIndex=0x484;
    };
    struct a_player_state {
        static constexpr std::uintptr_t Score=0x270, PlayerID=0x274, CompressedPing=0x278,
            StartTime=0x27c, UniqueID=0x280, EngineMessageClass=0x2b0, SavedNetworkAddress=0x2c0,
            PawnPrivate=0x2e8, PlayerNamePrivate=0x308;
    };
    struct a_player_camera_manager {
        static constexpr std::uintptr_t PCOwner=0x270, TransformComponent=0x278, DefaultFOV=0x284,
            DefaultOrthoWidth=0x28c, DefaultAspectRatio=0x294, ViewTarget=0x300, PendingViewTarget=0xc30,
            CameraCachePrivate=0x1590, LastFrameCameraCachePrivate=0x1eb0, ModifierList=0x27d0,
            FreeCamDistance=0x27f0, FreeCamOffset=0x27f8, ViewTargetOffset=0x2810;
    };
    struct a_hud {
        static constexpr std::uintptr_t PlayerOwner=0x270, CurrentTargetIndex=0x27c,
            PostRenderedActors=0x288, DebugDisplay=0x2a0, canvas=0x2c0, DebugCanvas=0x2c8;
    };
    struct a_camera_actor {
        static constexpr std::uintptr_t AutoActivateForPlayer=0x270, CameraComponent=0x278,
            SceneComponent=0x280, AspectRatio=0x28c, FOVAngle=0x290, PostProcessBlendWeight=0x294;
    };

    // ---------- Components -----------------------------------------------------
    struct u_actor_component {
        static constexpr std::uintptr_t PrimaryComponentTick=0x38, ComponentTags=0x68,
            AssetUserData=0x78, UCSSerializationIndex=0x90, CreationMethod=0xb9;
    };
    struct u_scene_component {
        static constexpr std::uintptr_t PhysicsVolume=0xc8, AttachParent=0xd0, AttachSocketName=0xd8,
            AttachChildren=0xe0, ClientAttachedChildren=0xf0, RelativeLocation=0x140,
            RelativeRotation=0x158, RelativeScale3D=0x170, ComponentVelocity=0x188;
    };
    struct u_primitive_component {
        static constexpr std::uintptr_t MinDrawDistance=0x278, LDMaxDrawDistance=0x27c,
            CachedMaxDrawDistance=0x280, DepthPriorityGroup=0x284, LightmapType=0x287;
    };
    struct u_mesh_component {
        static constexpr std::uintptr_t OverrideMaterials=0x568, OverlayMaterial=0x578,
            OverlayMaterialMaxDrawDistance=0x580;
    };
    struct u_skeletal_mesh_component {
        static constexpr std::uintptr_t AnimClass=0x900, AnimScriptInstance=0x908,
            OverridePostProcessAnimBP=0x910, PostProcessAnimInstance=0x918, AnimationData=0x920,
            RootBoneTranslation=0x938, LineCheckBoundsScale=0x950, LinkedInstances=0x990,
            CachedBoneSpaceTransforms=0x9a0, CachedComponentSpaceTransforms=0x9b0,
            GlobalAnimRateScale=0xa10, AnimationMode=0xa17;
    };
    struct u_static_mesh_component {
        static constexpr std::uintptr_t ForcedLodModel=0x5c8, MinLOD=0x5cc, SubDivisionStepSize=0x5d0,
            WireframeColorOverride=0x5d4, StaticMesh=0x5d8, WorldPositionOffsetDisableDistance=0x5e0;
    };
    struct u_capsule_component  { static constexpr std::uintptr_t CapsuleHalfHeight=0x588, CapsuleRadius=0x58c; };
    struct u_input_component    { static constexpr std::uintptr_t CachedKeyToActionInfo=0x130; };
    struct u_player_input       { static constexpr std::uintptr_t DebugExecBindings=0x160, InvertedAxis=0x1a0; };

    // ---------- Movement -------------------------------------------------------
    struct u_movement_component {
        static constexpr std::uintptr_t UpdatedComponent=0xc0, UpdatedPrimitive=0xc8,
            Velocity=0xd8, PlaneConstraintNormal=0xf0, PlaneConstraintOrigin=0x108;
    };
    struct u_pawn_movement_component { static constexpr std::uintptr_t PawnOwner=0x180; };
    struct u_character_movement_component {
        static constexpr std::uintptr_t CharacterOwner=0x198, GravityScale=0x1a0, MaxStepHeight=0x1a4,
            JumpZVelocity=0x1a8, WalkableFloorAngle=0x1cc, WalkableFloorZ=0x1d0,
            GravityDirection=0x1d8, MovementMode=0x231, GroundFriction=0x234,
            MaxWalkSpeed=0x278, MaxWalkSpeedCrouched=0x27c, MaxSwimSpeed=0x280, MaxFlySpeed=0x284;
    };
    struct u_camera_component {
        static constexpr std::uintptr_t FieldOfView=0x240, FirstPersonFieldOfView=0x244,
            FirstPersonScale=0x248, OrthoWidth=0x24c, AspectRatio=0x264, Overscan=0x26c;
    };
    struct u_cheat_manager {
        static constexpr std::uintptr_t DebugCameraControllerRef=0x28, DebugCameraControllerClass=0x30,
            CheatManagerExtensions=0x78;
    };

    // ---------- Fortnite building actors --------------------------------------
    struct a_building_actor {
        static constexpr std::uintptr_t MyGuid=0x368, SavedHealthPct=0x378, OwnerPersistentID=0x37c,
            AreaClass=0x380, CurrentBuildingLevel=0x3c0, BuildingAttributeSet=0x3d0,
            DamageAttributeSet=0x3d8, AbilitySystemComponent=0x408;
    };
    struct a_building_container {
        static constexpr std::uintptr_t SearchedMesh=0xb50, SearchLootTierGroup=0xba0,
            ContainerLootTierKey=0xba4, ReplicatedLootTier=0xbc0, ChosenRandomUpgrade=0xbc4,
            MarkerDisplay=0xbc8;
    };
    struct a_building_gameplay_actor {
        static constexpr std::uintptr_t InherentAbilitySets=0x6c8, DamageStatHandle=0x6f0,
            AbilitySourceLevel=0x76c, DeliverableAbilityInfo=0x770;
    };
    struct a_building_sm_actor {
        static constexpr std::uintptr_t TextureData=0x6d8, StaticMesh=0x6f8, ResourceType=0x701;
    };
    struct a_building_weak_spot {
        static constexpr std::uintptr_t ParentObject=0x298, HitCount=0x2a4, Level=0x2a8,
            MaxLevel=0x2ac, StartingLocation=0x2b0, HitNormal=0x2c8, PhysicalSurfaceType=0x2e0;
    };

    // ---------- Fortnite pawns / controllers / states -------------------------
    struct a_fort_ai_pawn {
        static constexpr std::uintptr_t DeimosBatchedGameplayCueParameters=0x1ec0,
            AttributeReplicationProxy=0x1f90, RepAnimMontageInfo=0x1fa0, RepSharedAnimInfo=0x1fd8,
            SimulatedProxyGameplayCues=0x1ff0, AnimationSharingSetup=0x22b8;
    };
    struct a_fort_pawn {
        static constexpr std::uintptr_t BatchedGameplayCueParameters=0x0;
    };
    struct a_fort_physics_pawn {
        static constexpr std::uintptr_t ReplicatedTransformReq=0x2f8, GravityMultiplier=0x330;
    };
    struct a_fort_player_pawn {
        static constexpr std::uintptr_t VehicleInputStateReliable=0x1f78;
    };
    struct a_fort_player_pawn_athena {
        static constexpr std::uintptr_t ItemInteractionActor=0x4940, PreviousVelocityXY=0x4968,
            OnReviveSound=0x4980, ReviveFromDBNOTime=0x4988, DBNOStartTime=0x4990,
            DBNOStartLocation=0x4998, DeathTime=0x49b0, DBNOInvulnerableTime=0x49b4,
            ItemSpecialActorID=0x49e0, LandEmitterTemplate=0x4a00;
    };
    struct a_fort_player_controller {
        static constexpr std::uintptr_t OnPlayerPawnPossessed=0x760, OnEnteredEditMode=0x770,
            OnPickupCreated=0x780, OnLoadoutChanged=0x790, OnViewTargetChanged=0x7d0,
            OnPlayerStateReady=0x810, OnFortPawnChangedEvent=0x850, HybridControlsComponentComponent=0x998,
            AircraftInputComponent=0x9c0, SprintOverrideComponent=0x9c8, SkydiveMusicAudioComp=0x9d0;
    };
    struct a_fort_player_controller_zone {
        static constexpr std::uintptr_t OnBeginSkydiving=0x2fe0, OnEndSkydiving=0x2ff0,
            LastVehicleSeatSwitchTime=0x3040, PlayerToSpectateOnDeath=0x3050,
            SpectatorModeComponent=0x30c0, MarkerComponent=0x30e8, PlayerDeathReport=0x3138;
    };
    struct a_fort_player_controller_athena {
        static constexpr std::uintptr_t FireAbilityToWeaponSwitchTime=0x3680,
            OnAircraftStateChange=0x36b0, SwappingItemDefinition=0x3718,
            WinScreenDelayTime=0x3720, FocalPoint=0x3728, FocalPointOffset=0x3730,
            FocalPointFOV=0x3748, FocalPointDuration=0x374c, SkydiveLeaderManualCameraTime=0x37e0,
            InterpolatedSkydiveFollowerViewRotation=0x37e8;
    };
    struct a_fort_player_state {
        static constexpr std::uintptr_t PlayerRole=0x38c, WorldPlayerId=0x38e, PartyOwnerUniqueId=0x390,
            HeroId=0x3c0, HeroType=0x3d0, CurrentCharXP=0x3d8, MyBackpackPickup=0x3dc,
            InitialExperienceLevel=0x3e4, Platform=0x400, Banner=0x410, CachedLoadoutCharacterInfo=0x438;
    };
    struct a_fort_player_state_zone {
        static constexpr std::uintptr_t OnCurrentPawnChanged=0xa60, SpectatingTarget=0xa88,
            Spectators=0xa90, KickedFromSessionReason=0xb78, CarriedObject=0xca8, NumRejoins=0xcb0,
            CurrentHealth=0xcd4, MaxHealth=0xcd8, CurrentShield=0xcdc;
    };
    struct a_fort_player_state_athena {
        static constexpr std::uintptr_t PersonalLobbyAction=0xe54, RespawnData=0xe58,
            OnSquadIdChangedDelegate=0xec8, TeamKillScore=0xf0c, TeamIndex=0xf31,
            TeamScorePlacement=0xf34, TeamScore=0xf38, Place=0xf40, DownScore=0xf44, KillScore=0xf48,
            SeasonLevelUIDisplay=0xf4c, HumanKillScore=0xf54, AIKillCount=0xf94,
            NumChestsOpened=0xf9c, NumAmmoCansOpened=0xfa4;
    };

    // ---------- Fortnite gameplay ---------------------------------------------
    struct a_fort_game_state {
        static constexpr std::uintptr_t CurrentWUID=0x350, ParTime=0x360, WorldLevel=0x364,
            CraftingBonus=0x368, TeamCount=0x370, MatchmakingLinkId=0x378, POIManager=0x3c0,
            MatchStartTime=0x3fc, RealMatchStartTime=0x400;
    };
    struct a_fort_game_state_athena {
        static constexpr std::uintptr_t PostGameUIInfo=0x1060, InfiniteBuildingResources=0x10f0,
            InfiniteGold=0x1118, InfiniteWorldResources=0x1140, AthenaGameDataTable=0x1190;
    };
    struct a_fort_inventory {
        static constexpr std::uintptr_t RecentlyAdded=0x278, RecentlyRemoved=0x288, RecentlyChanged=0x298,
            InventoryType=0x2b9, Inventory=0x2c0, PendingExistingItems=0x348, ReplayPawn=0x364;
    };
    struct a_fort_pickup {
        static constexpr std::uintptr_t PickupSourceTypeFlags=0x288, PickupSpawnSource=0x289,
            ServerImpactSoundFlash=0x28a, SimulatingTooLongLength=0x290;
    };
    struct a_fort_projectile_base {
        static constexpr std::uintptr_t VerticleFireOffset=0x670, InitialSpeed=0x680,
            ChargeUpInitialSpeed=0x690, MaxSpeed=0x6a0, InitialGravityScaleOverride=0x6b0,
            ReplicatedMaxSpeed=0x6c0, GravityScale=0x6c4, OriginalTarget=0x6c8, ChargePercent=0x6d0,
            MomentumTransfer=0x6d4, CapsuleComponent=0x750, ProjectileMovementComponent=0x758;
    };
    struct a_fort_weapon {
        static constexpr std::uintptr_t OnWeaponRateOfFireChanged=0x2b8,
            OnPressTrigger=0x2e0, OnReleaseTrigger=0x2f0, TimeToEquip=0x348,
            OnLocalAmmoChanged=0x420, OnLocalReloadStarted=0x430, OnReloadStarted=0x440;
    };
    struct a_fort_weapon_ranged {
        static constexpr std::uintptr_t OnProjectileSpawned=0x18d0, OnRecoilAdded=0x18e0,
            ReplayActivationCue=0x1928, ReplayImpactCue=0x1a00, TracerFXDataChannel=0x1b30,
            NDCTracerFx=0x1b38, MuzzleFXData=0x1c70, HitscanTracerFakeVelocity=0x1d20,
            TracerTemplate=0x1d28, LocalFireRateModification=0x1d58, CurrentNumBullets=0x1d5c,
            ScopeTargetingMuzzleOffset=0x1d60;
    };
    struct a_fort_safe_zone_indicator {
        static constexpr std::uintptr_t MinimapComp=0x270, PreviousRadius=0x278, NextRadius=0x27c,
            NextNextRadius=0x280, PreviousCenter=0x288, NextCenter=0x2a0, NextNextCenter=0x2b8,
            PreviousRotation=0x2d0, NextRotation=0x2d4, PlaylistMaxSafeZoneIndex=0x2f4;
    };
    struct a_fort_athena_aircraft {
        static constexpr std::uintptr_t NumSpawnSlots=0x304, SpawnOffsetRadius=0x308,
            FlightInfo=0x320, FlightStartTime=0x368, FlightEndTime=0x36c, DropStartTime=0x370,
            DropEndTime=0x374, ReplicatedFlightTimestamp=0x37c, MiniMapIconBrush=0x390;
    };
    struct a_fort_athena_supply_drop {
        static constexpr std::uintptr_t GroundCollsionProfile=0x920, WaveSpawnSoundCue=0x928,
            LootTableNameOverride=0x930, SpawnOffsetZ=0xa30, InStormDespawnTimeInSeconds=0xa50,
            LongInteractAudioComponent=0xa80, SpectatorMapIcon=0xa98;
    };
    struct a_fort_athena_vehicle {
        static constexpr std::uintptr_t VehicleContextTag=0x590, VehicleEventRouter=0x598,
            VehicleImpactDamageTag=0x5b0, CustomOwnerName=0x608, DefaultOwnerName=0x618,
            CustomName=0x658, PlayersBasedOnVehicle=0x6a0, LastDamageInstigator=0x758;
    };

    // ---------- Fortnite systems ----------------------------------------------
    struct u_fort_ability_system_component {
        static constexpr std::uintptr_t OnClientVehicleBlockingChanged=0xa68,
            LandingMontagePair=0xba8, LastResolvedEmoteMontage=0xbd0, RepSharedAnimInfo=0xbd8;
    };
    struct u_fort_cheat_manager {
        static constexpr std::uintptr_t AbilitySystemCycleCounter=0x9c, ForcedAILODValue=0xa0;
    };
    struct u_fort_game_viewport_client {
        static constexpr std::uintptr_t NetworkFailureMessage=0x398,
            NetworkFailureMessageAdditionalAnalyticsString=0x3a8;
    };
    struct u_fort_item {
        static constexpr std::uintptr_t OnItemChanged=0x48, OnItemDestroyed=0x70;
    };
    struct u_fort_movement_comp_character {
        static constexpr std::uintptr_t OnInputFilteredByProbe=0xfe8,
            OnCharacterLaunchedByPhysicsImpact=0x1020, MovementProbeSetups=0x1060,
            LandHardSoundFallSpeedThreshold=0x1088, LandSoundFallSpeedThreshold=0x108c,
            PushBumpedPawnClass=0x1090, StreamingMaxSpeed=0x1150, ClampMaxSpeedToStreamingSpread=0x1178;
    };

} // namespace off::v
