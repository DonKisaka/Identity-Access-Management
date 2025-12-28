package identityaccessmanagement.example.Identity.Access.Management.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Entity
@Table(name = "permissions")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Permission name cannot be blank")
    @Column(unique = true, nullable = false)
    private String name;

    @Column
    private String resource;

    @Column
    private String action;

    @Column
    private String description;


}
